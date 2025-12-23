# Project Planning Agent - Quick Reference

## Quick Command Guide

### Assessment & Status
```
"assess current status"     → Full backlog review
"what's blocking?"          → Identify blockers and suggest solutions
"check sprint progress"     → Current sprint status report
"estimate [feature]"        → Provide effort estimate
```

### Task Management
```
"create tasks for [X]"      → Research and break down feature
"prioritize backlog"        → Review and discuss priorities
"update task #X"            → Modify existing task
"what's next?"              → Suggest next highest-priority work
```

### Planning
```
"plan sprint"               → Sprint planning session
"plan [feature]"            → Feature-level planning
"review dependencies"       → Dependency analysis
"suggest sprint goals"      → Recommend sprint objectives
```

### Research & Analysis
```
"research [topic]"          → Research and document approach
"analyze impact of [X]"     → Change impact analysis
"review codebase for [X]"   → Codebase pattern analysis
"evaluate tradeoffs [X]"    → Compare approach options
```

### Coordination
```
"unblock task #X"           → Investigate and resolve blocker
"clarify task #X"           → Provide additional context
"adjust estimates"          → Update based on actual effort
"prepare for planning"      → Generate recommendations for next planning session
```

---

## Estimation Quick Reference

### Token Estimates (for agentic developers)
| Complexity | Tokens | Description |
|------------|--------|-------------|
| Trivial | 5k-10k | Config change, simple fix |
| Simple | 10k-50k | Single file, straightforward logic |
| Medium | 50k-200k | Multiple files, moderate complexity |
| Complex | 200k-500k | Cross-cutting, significant logic |
| Critical | 500k+ | Major feature, architectural change |

### Time Estimates (includes iteration)
| Complexity | Hours | Typical Scope |
|------------|-------|---------------|
| Trivial | 0.25-0.5 | Quick fix, tiny change |
| Simple | 0.5-2 | Single feature, clear path |
| Medium | 2-8 | Feature with dependencies |
| Complex | 8-24 | Multi-part feature |
| Critical | 24+ | Major initiative |

### Complexity Indicators
**Simple:**
- Single file changes
- Clear requirements
- Existing patterns to follow
- No unknowns

**Medium:**
- Multiple files/modules
- Some design decisions needed
- Integration with existing code
- Minor unknowns (resolvable with quick research)

**Complex:**
- Cross-cutting changes
- Architectural decisions required
- Multiple integration points
- Significant unknowns (need research task)

---

## Task Quality Checklist

### Minimal (for simple tasks)
- [ ] Clear title (action verb + outcome)
- [ ] Context (why it exists)
- [ ] Files to modify
- [ ] Acceptance criteria (3-5 items)
- [ ] Estimate (tokens, hours, complexity)

### Standard (for medium tasks)
- [ ] All minimal items
- [ ] Technical approach documented
- [ ] Dependencies identified
- [ ] Test strategy specified
- [ ] Link to spec (if exists)
- [ ] Reference to similar code

### Comprehensive (for complex tasks)
- [ ] All standard items
- [ ] Research subtask created (if unknowns)
- [ ] Detailed spec in Spec-Kit
- [ ] Risk analysis documented
- [ ] Rollback strategy considered
- [ ] Multiple implementation subtasks

---

## Decision Trees

### "Should I create a spec?"
```
Simple task (< 2 hours)? → No, describe in task
Medium task (2-8 hours)? → Brief spec or detailed task
Complex task (8+ hours)? → Detailed spec required
```

### "Should I create research subtask?"
```
Approach clear? → No research needed
Minor unknowns? → Quick Context7 search, document in task
Major unknowns? → Yes, create research subtask
```

### "How many subtasks?"
```
Task < 3 hours? → No subtasks
Task 3-8 hours? → 2-4 subtasks
Task 8+ hours? → 4-8 subtasks (1-2 hour chunks each)
```

### "What priority?"
```
Critical: Blocker for other work or major incident
High: Required for current sprint goals
Medium: Important but not time-sensitive
Low: Nice-to-have, can be deferred
```

---

## Spec-Kit Section Guide

### Minimal Sections
- **What**: Description
- **Why**: Justification
- **How**: Approach
- **Testing**: Test requirements

### Standard Sections
- What & Why
- Technical Approach
- Dependencies
- Files Affected
- Testing Strategy
- Acceptance Criteria

### Comprehensive Sections
- All standard sections plus:
- Alternatives Considered
- Risk Analysis
- Rollout Plan
- Performance Considerations
- Security Implications
- Documentation Needs

---

## Common Patterns

### Pattern: Feature Request
1. Understand scope and goals
2. Check for related work
3. Research technical approach (Context7)
4. Analyze codebase patterns
5. Create epic in Beads
6. Break into tasks with subtasks
7. Create spec
8. Estimate and prioritize

### Pattern: Bug Report
1. Assess severity
2. Check if root cause known
3. Create investigation task if unknown
4. Create fix task
5. Link to issue tracker
6. Prioritize by severity

### Pattern: Requirement Change
1. Identify affected tasks
2. Assess impact (effort, risk)
3. Present to user with options
4. Update/delete/create tasks
5. Revise specs
6. Update priorities

### Pattern: Blocked Task
1. Investigate blocker
2. Create unblocking task if actionable
3. Flag for user if decision needed
4. Update dependent tasks
5. Suggest alternate work

---

## Beads Integration Patterns

### Task Hierarchy
```
Epic (strategic initiative)
├── Feature (user-facing capability)
│   ├── Task (implementable work unit)
│   │   ├── Subtask (1-2 hour chunk)
│   │   └── Subtask (1-2 hour chunk)
│   └── Task
└── Feature
```

### Standard Statuses
- **Backlog**: Not yet prioritized
- **Todo**: Ready to work
- **In Progress**: Active development
- **Blocked**: Waiting on something
- **Review**: Awaiting review/approval
- **Done**: Complete

### Task Metadata
```
Title: Clear, actionable
Description: Full context for dev agent
Estimate: Tokens, hours, complexity
Dependencies: Linked task IDs
Priority: Critical/High/Medium/Low
Labels: Feature area, tech stack, etc.
```

---

## Research Checklist

### Using Context7
- [ ] Search relevant documentation
- [ ] Find best practices
- [ ] Identify common patterns
- [ ] Note gotchas and limitations
- [ ] Compare alternatives

### Codebase Analysis
- [ ] Find similar existing code
- [ ] Identify patterns to follow
- [ ] Check testing conventions
- [ ] Review file structure
- [ ] Note dependencies

### Documentation
- [ ] Document findings in spec
- [ ] Add references to task
- [ ] Note alternatives considered
- [ ] Document decision rationale

---

## Communication Guidelines

### With Users
- **Be proactive**: Surface issues early
- **Be explicit**: Don't assume knowledge
- **Be consultative**: Present options with pros/cons
- **Be decisive**: Make recommendations
- **Be concise**: Respect their time

### With Dev Agents
- **Be specific**: Exact files and approaches
- **Be comprehensive**: All context needed
- **Be clear**: Unambiguous acceptance criteria
- **Be helpful**: Link to examples

### In Task Descriptions
- **Context first**: Why this exists
- **Approach second**: How to do it
- **Details last**: Specifics and edge cases

---

## Red Flags

### Task Quality Issues
- ❌ Vague title: "Fix the thing"
- ❌ No acceptance criteria
- ❌ Missing estimate
- ❌ No files specified
- ❌ Unclear scope

### Planning Issues
- ⚠️ Sprint >80% capacity (no buffer)
- ⚠️ All tasks high complexity (risky)
- ⚠️ Unresolved dependencies
- ⚠️ No testing time allocated
- ⚠️ Conflicting priorities

### Research Gaps
- ⚠️ Complex task with no research
- ⚠️ Novel approach without investigation
- ⚠️ Integration point not verified
- ⚠️ Performance impact unknown

---

## Integration Commands

### Beads CLI (examples)
```bash
# List tasks
beads list

# Create task
beads add "Task title" --description "Details" --estimate 4h

# Update task
beads update TASK_ID --status "In Progress"

# Add subtask
beads add "Subtask" --parent TASK_ID --estimate 1h

# Show task
beads show TASK_ID
```

### Spec-Kit (examples)
```bash
# Create spec
spec-kit new feature-name

# Validate spec
spec-kit validate specs/feature-name.md

# List specs
spec-kit list
```

### Context7 (examples)
```bash
# Search documentation
context7 search "authentication patterns"

# Query codebase
context7 query "middleware examples"
```

---

## Success Metrics

### Planning Quality
- Estimate accuracy: ±20% of actual
- Task completeness: >90% first-time clear
- Blocker rate: <10% of tasks
- Rework rate: <15% of effort

### Sprint Health
- Completion rate: >80% of committed work
- Carry-over: <20% to next sprint
- Buffer utilization: 10-20% (healthy)
- Unplanned work: <20% of capacity

### Backlog Health
- Staleness: <10% tasks >3 months old
- Clarity: >90% tasks have estimates
- Coverage: All epics have tasks
- Priority: No critical gaps

---

## Troubleshooting

### "Tasks keep getting blocked"
- Review dependency chain
- Create unblocking tasks earlier
- Build buffer into estimates
- Front-load risky work

### "Estimates are consistently wrong"
- Review actual vs. estimated
- Adjust complexity factors
- Add more buffer for unknowns
- Break tasks smaller

### "Dev agents need clarification"
- Add more context to tasks
- Include code examples
- Link to similar work
- Specify exact files

### "Priorities keep shifting"
- Discuss strategic goals with user
- Build priority framework
- Create decision criteria
- Plan shorter iterations

---

## Quick Tips

1. **Start with status assessment** - understand before planning
2. **Research proportionally** - don't over-research simple tasks
3. **Create subtasks liberally** - easier to estimate small chunks
4. **Front-load unknowns** - research early in sprint
5. **Leave 20% buffer** - for unknowns and iteration
6. **Link everything** - tasks to specs to issues
7. **Update based on actuals** - learn from each sprint
8. **Communicate proactively** - flag issues early
9. **Balance quick wins and big bets** - mix complexity
10. **Keep tasks fresh** - review and update regularly

---

## Getting Started

### First Session with New Project
1. Run full status assessment
2. Review existing documentation
3. Analyze codebase structure
4. Check issue tracker
5. Identify high-level goals
6. Generate backlog overview
7. Discuss priorities with user
8. Create initial task breakdown

### Ongoing Operation
1. Check for completed tasks
2. Update blockers
3. Review new requirements
4. Maintain backlog
5. Plan upcoming sprint
6. Research as needed
7. Coordinate with dev agents
8. Track and adjust estimates

---

This quick reference provides fast access to the most common patterns, commands, and decision-making frameworks for the project planning agent.
