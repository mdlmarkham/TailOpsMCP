# Project Planning Agent - Practical Examples

## Example 1: Simple Task Creation

### User Request
"We need to add a health check endpoint to the API"

### Agent Response

**Status Assessment:**
Reviewing project... Found existing Express API in `src/server.js`. No health check endpoint currently exists.

**Research Summary:**
- Standard pattern: GET /health returns 200 with basic status
- Existing API uses Express middleware pattern
- Similar endpoints in `src/routes/status.js`

**Creating Task in Beads:**

```
Title: Add /health endpoint to API

Description:
Context: Need basic health check for load balancer monitoring.

Approach:
- Add GET /health route to src/server.js
- Return JSON: { status: 'ok', timestamp: ISO-8601 }
- Always return 200 unless server is shutting down
- No authentication required

Files to modify:
- src/server.js (add route before error handlers)
- tests/api/health.test.js (create new test file)

Acceptance Criteria:
- GET /health returns 200 with correct JSON structure
- Response time < 50ms
- Works without authentication
- Test coverage 100%

Reference: See src/routes/status.js for similar simple endpoint pattern

Estimated: 15k tokens, 1 hour, Low complexity
Dependencies: None
```

**No spec needed** - too simple, approach is straightforward

---

## Example 2: Medium Complexity Feature

### User Request
"Add rate limiting to protect against API abuse"

### Agent Response

**Status Assessment:**
Current API has no rate limiting. Need to protect all endpoints except /health.

**Research Phase:**
*[Creates research subtask in Beads]*

```
Subtask: Research rate limiting approach

- Investigate: express-rate-limit vs. redis-based solutions
- Check: Existing Redis connection in project
- Analyze: Current request volume and appropriate limits
- Review: Error handling patterns for 429 responses

Estimated: 10k tokens, 0.5 hours
```

*[After research using Context7 and codebase analysis]*

**Research Findings:**
- express-rate-limit is lightweight and sufficient for current scale
- No Redis in stack yet (overkill for current needs)
- Existing error middleware can handle 429s
- Recommendation: In-memory store, 100 req/15min per IP

**Creating Spec-Kit Spec:**

`specs/rate-limiting.md`:
```markdown
# Rate Limiting Implementation

## Overview
Protect API from abuse by limiting request rate per IP address.

## Why
- Prevent DOS attacks
- Ensure fair resource distribution
- Reduce server load from misbehaving clients

## Technical Approach
Use express-rate-limit with in-memory store.

### Configuration
- Window: 15 minutes
- Max requests: 100 per window
- Key: IP address (req.ip)
- Exemptions: /health endpoint
- Response: 429 with Retry-After header

### Implementation Details
- Add as early middleware in src/server.js
- Configure before route definitions
- Use existing error response format
- Add rate limit headers to all responses:
  - X-RateLimit-Limit
  - X-RateLimit-Remaining
  - X-RateLimit-Reset

## Dependencies
- Package: express-rate-limit ^6.x
- Existing: Express error middleware

## Files Affected
- src/server.js (add middleware)
- src/config/rateLimit.js (create config)
- tests/middleware/rateLimit.test.js (create)
- package.json (add dependency)

## Testing Strategy
- Unit: Middleware config correct
- Integration: Rate limit enforced correctly
- Integration: Exempt endpoints work
- Integration: Headers present in responses
- Load: Performance impact negligible

## Acceptance Criteria
1. Clients limited to 100 req/15min per IP
2. 429 responses include Retry-After
3. /health endpoint exempt
4. Rate limit headers on all responses
5. Tests achieve 95%+ coverage
6. No performance degradation < 100 req/s

## Risks
- In-memory store resets on server restart (acceptable for current scale)
- May need Redis later if deployed across multiple instances
- IP-based limiting can be evaded (acceptable for now)

## Future Considerations
- Move to Redis when scaling horizontally
- Add authenticated user rate limiting
- Implement tiered limits for different user types
```

**Creating Tasks in Beads:**

```
Epic: API Rate Limiting

├── Task: Configure rate limiting middleware
│   Description: [as above, pointing to spec]
│   Estimated: 40k tokens, 2.5 hours, Medium complexity
│   └── Subtask: Add express-rate-limit package
│       Estimated: 5k tokens, 0.3 hours
│   └── Subtask: Create rate limit config module
│       Estimated: 15k tokens, 1 hour
│   └── Subtask: Integrate middleware in server.js
│       Estimated: 10k tokens, 0.5 hours
│   └── Subtask: Add rate limit tests
│       Estimated: 20k tokens, 1.5 hours
│
└── Task: Document rate limiting in API docs
    Estimated: 10k tokens, 0.5 hours, Low complexity
```

**User Discussion:**
"I've created a spec and tasks for rate limiting. Key decision: using in-memory store with express-rate-limit. This is simpler and sufficient for current single-instance deployment, but we'll need Redis when scaling horizontally. Limits set to 100 req/15min per IP - does this align with expected usage patterns? Should we make this configurable via env vars?"

---

## Example 3: Complex Feature Requiring Deep Research

### User Request
"Implement real-time collaborative editing in the document editor"

### Agent Response

**Initial Assessment:**
This is a complex feature requiring significant research and architectural decisions.

**Risk/Tradeoff Discussion:**

"Real-time collaboration is high complexity. Key considerations:

**Tradeoffs:**
1. **Operational Transform (OT) vs. CRDT**
   - OT: More mature, complex to implement correctly
   - CRDT: Mathematically sound, larger data overhead
   - Recommendation: CRDT (Yjs) for reliability

2. **Infrastructure needs:**
   - WebSocket server required
   - State synchronization mechanism
   - Conflict resolution strategy
   - Offline support considerations

3. **Effort estimate:**
   - Research: 50k tokens, 4 hours
   - Core implementation: 300k tokens, 20 hours
   - Testing/polish: 100k tokens, 8 hours
   - Total: ~450k tokens, 32 hours over multiple sprints

**Risks:**
- Complex state management
- Potential data corruption if implementation flawed
- Performance impact on large documents
- Scaling challenges with many concurrent users

**Recommendation:**
Create detailed research phase first, then POC, then full implementation. Budget 2-3 sprints minimum.

Should we proceed? Alternative: simpler locking mechanism for MVP?"

*[After user approval]*

**Creating Research Phase:**

```
Epic: Real-time Collaborative Editing

├── Task: Research collaborative editing approaches [CURRENT]
│   Description:
│   Research and document technical approach for real-time collaboration.
│   
│   Research areas:
│   1. CRDT libraries (Yjs, Automerge) - evaluate for our use case
│   2. WebSocket architecture - integration with existing stack
│   3. State sync strategies - handle offline/reconnection
│   4. Editor integration - compatibility with current editor
│   5. Data model changes - schema migrations needed
│   6. Conflict resolution - edge cases and handling
│   
│   Deliverables:
│   - Detailed technical spec with chosen approach
│   - POC plan with success criteria
│   - Implementation task breakdown
│   - Risk mitigation strategies
│   
│   Use Context7 to research:
│   - Yjs documentation and best practices
│   - WebSocket patterns with Express
│   - Real-time collaboration architecture examples
│   
│   Analyze codebase for:
│   - Current editor implementation (src/components/Editor/)
│   - Document data model (src/models/Document.js)
│   - WebSocket infrastructure (if any exists)
│   
│   Estimated: 80k tokens, 6 hours, High complexity
│   Dependencies: None
│
├── [Tasks will be created after research complete]
```

**Status Update:**
"Created research task as first step. This will generate a comprehensive spec and implementation plan. Once research complete, I'll break this into phased tasks:
1. POC (WebSocket + basic Yjs sync)
2. Editor integration
3. Conflict handling
4. Polish and scale

Estimated 3 sprints total. I'll check in after research phase to review approach before committing to full implementation."

---

## Example 4: Handling Requirement Change

### User Request
"Actually, we're pivoting away from multi-tenancy. Single tenant per instance now."

### Agent Response

**Impact Analysis:**

Analyzing backlog... This affects 12 tasks:

**High Impact (In Progress):**
1. ❌ **Task #45: Multi-tenant data isolation** (50% complete, 15 hours invested)
   - Current: Adding tenant_id to all queries
   - Impact: Completely obsolete, code should be removed
   - Action: Stop work immediately, create cleanup task

2. ⚠️ **Task #47: Tenant-aware caching** (not started)
   - Impact: Entire approach changes - much simpler without multi-tenancy
   - Action: Delete task, create new simpler caching task

**Medium Impact (Planned):**
3-8. Six database migration tasks planned for tenant_id columns
   - Action: Delete all, saves ~30 hours estimated effort

**Low Impact (Can Adapt):**
9. **Task #52: User authentication**
   - Impact: Remove tenant selection logic
   - Action: Update task, remove 20% of scope (-5 hours)

10-12. Three UI tasks can be simplified by removing tenant switcher

**Summary:**
- 12 tasks affected
- 45 hours of planned work eliminated
- 15 hours of in-progress work to rollback
- Net effort reduction: ~60 hours
- Need to create: 3 cleanup tasks (10 hours)

**Immediate Actions Needed:**
1. Stop work on Task #45 immediately
2. Create rollback task to remove tenant_id code
3. Update authentication task scope
4. Delete obsolete database migration tasks

**Risks:**
- Existing tenant_id code in codebase needs cleanup
- Database schema partially migrated (need rollback migration)
- Some assumptions in specs need revision

**Recommendations:**
1. Prioritize cleanup tasks before new feature work
2. Update architecture docs to reflect single-tenant model
3. Review all "planned" tasks for multi-tenancy assumptions
4. Create new simplified caching task

**Shall I proceed with these changes? The cleanup will take about 1 sprint to fully resolve.**

*[After user approval]*

**Executing Updates:**

Created tasks:
- ✅ Task #78: Rollback tenant_id database migrations (8 hours)
- ✅ Task #79: Remove tenant isolation code (6 hours) 
- ✅ Task #80: Simplify authentication (remove tenant selection) (4 hours)

Deleted tasks: #47, #53-58 (6 tasks)

Updated tasks: #52 (reduced scope)

Updated specs:
- authentication.md (removed multi-tenant sections)
- caching.md (simplified approach)

**Status:** Backlog updated. Cleanup tasks prioritized for next sprint. Net savings: 42 hours after cleanup investment.

---

## Example 5: Sprint Planning Session

### User Request
"Plan next sprint. We have 40 hours capacity, two dev agents, and need to ship user profiles feature."

### Agent Response

**Sprint Planning - Week of [Date]**

**Constraints:**
- Duration: 40 hours total (20 hours per dev agent)
- Must-have: User profiles feature
- Team: 2 dev agents

**Analysis:**

User profiles epic has 8 tasks, 52 hours estimated. Won't fit in one sprint.

**Proposed Sprint Scope:**

**Critical Path (User Profiles MVP):**
1. Task #34: User profile data model (8h) [High]
2. Task #35: Profile API endpoints (6h) [High] - depends on #34
3. Task #36: Profile edit UI (10h) [High] - depends on #35
4. Task #37: Avatar upload (8h) [Medium] - depends on #34

Subtotal: 32 hours (80% of capacity)

**Buffer Tasks (if ahead of schedule):**
5. Task #41: Profile privacy settings (6h) [Medium] - depends on #35
6. Task #42: Email preferences (4h) [Low] - independent

**Deferred to Next Sprint:**
- Task #38: Social profile links (5h)
- Task #39: Profile themes (7h)

**Dependency Order:**
```
Sprint Start
├── Dev Agent 1: Task #34 (8h)
│   └── Task #35 (6h)
│       └── Task #41 if time (6h)
│
└── Dev Agent 2: Task #36 (10h) - starts after #35 done
    └── Task #37 (8h)
        └── Task #42 if time (4h)
```

**Risk Assessment:**
- ⚠️ Task #37 (avatar upload) has unknowns around file storage
  - Mitigation: Research subtask exists, prioritize early
- ✅ Tasks #34-36 are well-defined, low risk
- ⚠️ 32/40 hours is tight (80% utilization)
  - Buffer: Tasks #41-42 are optional stretch goals

**Recommendations:**
1. Start with Task #34 (foundational)
2. Dev Agent 2 can work on Task #36 UI shell while #35 is being built
3. Have file storage decision ready before starting Task #37
4. If running ahead, add buffer tasks in priority order
5. If running behind, defer Task #37 to next sprint (profiles work without avatars)

**Sprint Goal:**
"Users can create, view, and edit their profiles with basic information and avatars."

**Success Metrics:**
- All 4 critical path tasks completed
- User can fully edit their profile
- Tests pass, code reviewed
- Deployed to staging

**Next Sprint Preview:**
If we complete MVP, next sprint adds:
- Social links
- Profile themes  
- Privacy settings (if not done)
- Polish and bug fixes

**Shall I create a sprint milestone in Spec-Kit and flag these tasks in Beads?**

---

## Example 6: Blocked Task Investigation

### Dev Agent Message in Beads Task
"Task #56 blocked - integration tests failing, API returns 403 but should be 200. Can't reproduce in local env."

### Planning Agent Response

**Investigating Blocker - Task #56**

Analyzing issue...

**Context:**
- Task: Implement document sharing
- Symptom: 403 errors in integration tests, works locally
- Environment difference suspected

**Investigation Steps:**

1. **Review test environment config:**
   - Found: `TEST_AUTH_BYPASS=false` in CI but `true` locally
   - Cause: Tests assume auth bypass but CI enforces real auth

2. **Check related changes:**
   - Task #54 (auth middleware) merged yesterday
   - Modified auth flow, stricter validation
   - Tests not updated for new auth requirements

**Root Cause:**
Tests need valid JWT tokens but are sending requests without auth headers.

**Solution Options:**

**Option A: Update tests to use auth (Recommended)**
- Pro: Tests real auth flow, catches auth bugs
- Pro: Matches production behavior
- Con: Requires test user setup (2 hours)

**Option B: Re-enable auth bypass in tests**
- Pro: Quick fix (30 mins)
- Con: Doesn't test real auth flow
- Con: Could miss auth-related bugs

**Recommendation:**
Choose Option A. Create new subtask.

**Creating Unblocking Task:**

```
Task #82: Add auth test helpers

Context: Integration tests need proper auth setup after auth middleware changes.

Approach:
- Create test/helpers/auth.js
- Implement getTestToken() - generates valid JWT for test user
- Update all integration tests to use auth helper
- Ensure test user has necessary permissions

Files to modify:
- test/helpers/auth.js (create)
- test/integration/*.test.js (update 12 test files)
- test/setup.js (add test user creation)

Acceptance Criteria:
- All integration tests pass in CI
- Tests use real auth flow
- Helper is reusable for future tests
- Test coverage maintained

Estimated: 25k tokens, 2 hours, Medium complexity
Priority: High (blocks Task #56)

Blocks: Task #56
```

**Updated Task #56:**
- Status: Blocked → Waiting
- Blocked by: Task #82 (auth test helpers)
- Note: Can resume after #82 complete, no rework needed

**Sprint Impact:**
- Task #56 delayed 2 hours
- Task #82 not in original sprint plan (buffer time)
- If buffer insufficient, may need to defer lower-priority task

**Dev Agent:** "Task #82 created and prioritized. Once you complete that, Task #56 should unblock. In the meantime, you could work on Task #60 (independent) to maintain momentum."

---

## Example 7: Technical Debt Assessment

### User Request
"Should we refactor the auth system? It's getting messy."

### Agent Response

**Technical Debt Assessment: Auth System**

**Current State Analysis:**

Analyzing `src/auth/`...

**Issues Identified:**
1. **Complexity**: 847 lines in auth.js (recommended: <300)
2. **Coupling**: Auth logic mixed with session, JWT, and OAuth
3. **Duplication**: Token validation repeated in 5 places
4. **Testing**: 67% coverage (should be 90%+)
5. **Tech Debt**: 4 TODO comments, 2 deprecation warnings

**Codebase Impact:**
- 23 files import auth module
- Auth changes cause cascading test failures
- New auth providers require modifying core auth.js

**Cost/Benefit Analysis:**

**Cost of Refactoring:**
- Time: 60-80 hours (4-5 sprints)
- Risk: High (core system, easy to break)
- Opportunity cost: Delays feature work
- Testing effort: Significant (regression risk)

**Cost of NOT Refactoring:**
- Velocity impact: 10-15% slower auth-related features
- Bug risk: Medium (complexity breeds bugs)
- Onboarding: Harder for new developers
- Future cost: Debt compounds over time

**Break-Even Analysis:**
If we do 4+ auth-related features in next 6 months, refactoring pays for itself.

**Recommendation:**

**Option A: Incremental Refactoring (Recommended)**
- Refactor in phases during feature work
- Extract token validation first (1 sprint, 15 hours)
- Split OAuth providers next (1 sprint, 20 hours)
- Improve tests alongside (ongoing)
- Pro: Lower risk, delivers value while refactoring
- Con: Takes longer overall

**Option B: Dedicated Refactoring Sprint**
- Block 2 sprints for complete rewrite
- Pro: Clean slate, best final architecture
- Con: No feature progress, higher risk

**Option C: Defer**
- Continue with current system
- Only refactor if becomes critical blocker
- Pro: No immediate investment
- Con: Debt grows, harder later

**My Recommendation: Option A**
1. Next time we need auth work, extract token validation (15h)
2. Sprint after that, split OAuth (20h)  
3. Continuously improve test coverage
4. Revisit in 3 months for final cleanup

**Proposed Tasks (if approved):**
```
Epic: Auth System Refactoring

├── Task: Extract token validation module
│   Timing: Next sprint with auth feature work
│   Estimated: 15 hours
│
├── Task: Split OAuth providers to plugins
│   Timing: Following sprint
│   Estimated: 20 hours
│
└── Task: Improve auth test coverage to 90%
    Timing: Ongoing
    Estimated: 10 hours spread across sprints
```

**Decision needed:** Approve incremental refactoring approach? This adds 15 hours to next sprint if we proceed.

---

## Example 8: Estimating Complex Work

### User Request
"How long to build a GraphQL API layer on top of our REST API?"

### Agent Response

**Effort Estimation: GraphQL API Layer**

**Research Phase** (2 hours):
Using Context7 to investigate...

**Findings:**
- Existing: 47 REST endpoints across 8 controllers
- Stack: Express + PostgreSQL
- Need: GraphQL schema, resolvers, subscriptions optional

**Complexity Analysis:**

**Low Complexity (30%):**
- Simple CRUD operations with 1:1 REST mapping
- ~14 endpoints: User profile, settings, basic lists
- Pattern: REST → GraphQL resolver (straightforward)

**Medium Complexity (50%):**
- Nested resources, multiple joins
- ~24 endpoints: Documents, teams, permissions
- Pattern: Need batching/DataLoader for N+1 prevention

**High Complexity (20%):**
- Complex business logic, transactions
- ~9 endpoints: Document collaboration, billing
- Pattern: May need resolver refactoring

**Estimation by Phase:**

**Phase 1: Foundation (20 hours)**
- Apollo Server setup: 4 hours
- Base schema architecture: 6 hours
- Resolver pattern + DataLoader: 6 hours
- Error handling: 4 hours

**Phase 2: Schema & Resolvers (80 hours)**
- Type definitions: 15 hours (47 endpoints × ~20min)
- Simple resolvers (14 endpoints): 14 hours
- Medium resolvers (24 endpoints): 36 hours (1.5h each)
- Complex resolvers (9 endpoints): 27 hours (3h each)
- Input validation: 8 hours

**Phase 3: Features (30 hours)**
- Authentication/authorization: 10 hours
- Pagination/filtering: 8 hours
- Real-time subscriptions: 12 hours (if needed)

**Phase 4: Testing & Docs (25 hours)**
- Unit tests (90% coverage): 15 hours
- Integration tests: 6 hours
- GraphQL playground: 2 hours
- Documentation: 2 hours

**Total Estimates:**
- **Token estimate**: 750k-900k tokens
- **Time estimate**: 135-155 hours
- **Sprints**: 7-8 sprints (assuming 20h/sprint)
- **Complexity**: High (new technology + large surface area)

**Risk Factors:**
- ⚠️ N+1 query problem (can kill performance)
- ⚠️ Team learning curve with GraphQL
- ⚠️ Schema design decisions affect future flexibility
- ⚠️ Potential REST API refactoring needed

**Mitigation:**
- POC first (1 sprint): Build 3 endpoints to validate approach
- DataLoader from day 1 (prevent N+1)
- Schema review sessions with team
- Incremental rollout (parallel to REST initially)

**Alternative Approaches:**

**Option A: Full Build (155 hours)**
- Recommended if: GraphQL is strategic, REST will be deprecated
- Timeline: 8 sprints

**Option B: Incremental (120 hours)**
- Start with 10 most-used endpoints
- Validate approach and performance
- Build rest based on learnings
- Recommended if: Testing waters, keep REST

**Option C: Generated Layer (80 hours)**
- Use tool like PostGraphile or Hasura
- Pro: Much faster
- Con: Less control, may not fit all use cases

**Recommendation:**
Go with **Option B** (Incremental):
1. POC with 3 endpoints (1 sprint, 20h)
2. Build top 10 endpoints (2 sprints, 40h)
3. Evaluate performance and DX
4. Decide on full rollout or hybrid approach

**Next Steps:**
Want me to:
1. Create POC task with specific endpoint selection?
2. Break down into sprint-sized tasks?
3. Research alternative approaches (PostGraphile, etc.)?

---

## Communication Templates

### Good Task Description Template
```
Title: [Action verb] [specific outcome]

Context:
[Why this task exists, what problem it solves]

Approach:
[High-level strategy, key decisions made]
- [Specific step 1]
- [Specific step 2]
- [Specific step 3]

Files to modify/create:
- [Path/file.js] (create/modify) - [what changes]
- [Path/test.js] (create) - [test coverage]

Acceptance Criteria:
1. [Specific, testable outcome]
2. [Specific, testable outcome]
3. [Test coverage requirement]

Reference:
[Links to specs, similar code, docs]

Technical Notes:
[Any gotchas, edge cases, or important details]

Estimated: [X]k tokens, [Y] hours, [Low/Medium/High] complexity
Dependencies: [Task IDs or "None"]
```

### Status Report Template
```
Project Status - [Date]

Current State:
- [X] tasks total ([Y] complete, [Z] in progress, [W] blocked)
- Sprint [N] - Day [M] of [D]
- [X%] of current sprint complete

Recent Completions:
- Task #[X]: [Brief description] ✅
- Task #[Y]: [Brief description] ✅

In Progress:
- Task #[X]: [Brief description] - [N%] complete
- Task #[Y]: [Brief description] - on track

Blockers:
- Task #[X]: [Description] - [Blocker details]
- [Action being taken]

Upcoming:
- Task #[X]: Next in queue
- Task #[Y]: After dependencies resolve

Risks/Issues:
- [Risk description] - [Mitigation plan]

Recommendations:
- [Suggested action 1]
- [Suggested action 2]

Next Steps:
[What should happen next]
```

### Impact Analysis Template
```
Change Impact Analysis - [Requirement Change]

Affected Areas:
1. [Area 1]: [Impact description]
2. [Area 2]: [Impact description]

Affected Tasks:
Critical (must change):
- Task #[X]: [Description] - [Current status] - [Action needed]

Moderate (should review):
- Task #[Y]: [Description] - [Potential impact]

Minor (FYI):
- Task #[Z]: [Description] - [Minimal impact]

Effort Analysis:
- Eliminated work: [X] hours
- New work required: [Y] hours
- Rework needed: [Z] hours
- Net change: [+/-N] hours

Risks:
- [Risk 1]: [Description and mitigation]
- [Risk 2]: [Description and mitigation]

Recommendations:
1. [Recommended action]
2. [Recommended action]

Decisions Needed:
- [Question 1]?
- [Question 2]?

Timeline Impact:
[Effect on current and future sprints]
```

---

These examples demonstrate the planning agent's approach across various scenarios, always balancing thoroughness with efficiency and maintaining clear communication with users and dev agents.
