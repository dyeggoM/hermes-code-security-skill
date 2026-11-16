# Making a borrowed credential revocable

Applies to any token that stands in for someone else: role impersonation, support access, a scoped
share link, a short-lived delegation. All of them share the defect — the token is the whole state, so
nothing can end it early, detect a second end, or report what it touched.

## Not .NET?

The recipe below is written in C# because that is where it was implemented and measured. The four
pieces map one to one onto any stack:

| Here | Elsewhere |
|---|---|
| entity + `DbSet` + migration | model/table + migration (SQLAlchemy `DeclarativeBase`, Django `models.Model`, Prisma `model`) |
| `OnTokenValidated` | the place every request already passes: auth middleware, a dependency, a policy handler |
| the interceptor that writes the audit row | the same hook in your ORM (`after_flush`, `post_save`) or a trigger |
| `context.Fail("ended")` | reject the request as unauthenticated, before authorization runs |

The property that matters is not the framework: the liveness check must run **before** authorization,
so a closed borrow fails as a dead credential rather than as a forbidden action, and the end path must
not depend on the credential it is closing.

## The shape

Four pieces, in this order.

1. **A row per borrow.**

```csharp
public sealed class ImpersonationSession
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N"); // travels in a claim
    public string ActorUserId { get; set; } = "";
    public string? ActorEmail { get; set; }
    public string TargetRole { get; set; } = "";
    public DateTime StartedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? EndedAtUtc { get; set; }      // null while live
    public string? EndedBy { get; set; }           // "api" | "expired" | user id
}
```

Register the `DbSet`, map the string lengths, index `ActorUserId`, and generate the migration. Apply
it to the dev database *before* restarting the service, or the new column silently 500s on the first
write.

2. **The id in the token**, next to the existing actor claims (`act`, `act_email`,
   `impersonated_role`, `scope=read`). Expiry of the token is the row's expiry, not a second constant:
   pass `session.ExpiresAtUtc` into the token factory so the two cannot drift.

3. **The check where tokens are validated** (`OnTokenValidated` or the equivalent), only when the
   delegation claim is present:

```csharp
if (actorId is not null)
{
    var sessionId = principal.FindFirst("imp_sid")?.Value;
    var live = !string.IsNullOrWhiteSpace(sessionId) && await db.ImpersonationSessions.AsNoTracking()
        .AnyAsync(s => s.Id == sessionId && s.ActorUserId == actorId
            && s.EndedAtUtc == null && s.ExpiresAtUtc > DateTime.UtcNow);
    if (!live) context.Fail("The impersonation has ended.");
}
```

One query, only on delegated tokens — normal requests pay nothing.

4. **The end route**: find the row by `imp_sid` + actor, close it once, audit it, then mint the
   actor's token **only** if proof of the actor's own session arrived (their refresh cookie, hashed
   and matched against a live, unrevoked row of that same user). With no proof: `204` and no body.

```csharp
if (session is null || session.EndedAtUtc is not null) return Forbid(); // already ended / unknown
session.EndedAtUtc = DateTime.UtcNow;
session.EndedBy = "api";
await _context.SaveChangesAsync(ct);
await _audit.WriteAsync("ImpersonateEnd", "UserRole", role, actor.Id, actor.Email, ct,
    afterJson: JsonSerializer.Serialize(new { role, impersonation_session = session.Id }),
    impersonationSessionId: session.Id);          // explicit: the actor's own token has no imp_sid

if (!Request.Cookies.TryGetValue(RefreshCookie, out var actorRefresh)) return NoContent();
if (!await OwnsLiveSession(actor, actorRefresh)) return NoContent();
var access = await _tokens.CreateAccessTokenAsync(actor);
return Ok(new { access_token = access.Token, expires_at_utc = access.ExpiresAtUtc });
```

## The audit half

- Add `ImpersonationSessionId` to the audit entity and to the append-only insert statement — if the
  interceptor writes rows with raw SQL, its column list is the second place to change, and forgetting
  it fails at runtime, not at build.
- Fill it from the claim for rows written *inside* a borrow, and pass it explicitly for Start/End,
  which are written from outside (the actor's own token, or the token being closed).
- Exclude the session entity from the interceptor's change set: `entry.Entity is not AuditLog and not
  ImpersonationSession`. Otherwise each close writes an `Update` row against the control table.

## What to assert

One test per property, not one per endpoint:

| Property | Probe | Expected |
|---|---|---|
| live borrow reads | delegated token → `GET` a protected route | `200` |
| still read-only | delegated token → `POST`/`PATCH` | `403` |
| end without proof | `POST stop` with the delegated token only | `204`, body has no `access_token` |
| revocation is immediate | same token after the end | `401` (not `403`: it dies in authentication) |
| single use | second `POST stop` | `401` — nothing live to make it with |
| expiry | set `ExpiresAtUtc` in the past, then `GET` | `401` |
| handback | `POST stop` with the actor's cookie + delegated token | `200`, token carries the actor's role and no `act` |
| trail | query audit rows by session id | exactly the Start/End pair, both with the id, no control-table `Update` |

Then drive the real screen once: enter the delegation, click exit, confirm the banner clears, the
actor's session is back and the closing audit row exists. The store usually keeps the original token
as a fallback — verify it is what comes back, not an empty session.

## Residuals to state, not hide

- A delegation by *role* has no target user: `ImpersonatedUserId` stays null and the session id is the
  only correlator. Say that in the roadmap/docs instead of leaving a column that looks unfilled.
- Sessions accumulate. A sweeper that closes expired rows is a follow-up, not part of the fix; the
  liveness check already treats an expired row as dead.
