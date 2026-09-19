# Location Architecture

**Status:** Active
**Last updated:** 2026-09-15
**Owner:** Backend

This document is the single source of truth for how "location" is modeled
across the ERP. Every PR that touches a location column, or filters data by
location, must reference this document.

---

## 1. The four location dimensions

There are exactly **four** location concepts. Do not introduce synonyms.

| Concept | Backing table | Answers the question | Referenced by |
|---|---|---|---|
| **Request Location** | `public.locations` | "Where is the admin operating?" | `X-Location-ID` header → request ctx |
| **Employment Location** | `public.locations` | "Where does this employee or student belong?" | `company_employees.employment_location_id`, `academics.students.location_id` |
| **Geofence** | `attendance.geofences` | "Which physical fence / zone is this?" | `attendance_devices.geofence_id`, `attendance_events.geofence_id` |
| **Resource Location** | `public.locations` | "Where does this business object live?" | `<table>.location_id` (FK to `public.locations`) |

**Rules:**

1. Request Location and Employment Location share the **same** table
   (`public.locations`). They are distinguished by *who is asking*, not by
   which table is queried.
2. A Geofence is a **sub-dimension** of an Employment Location. Every
   geofence belongs to exactly one employment location
   (`attendance.geofences.employment_location_id`).
3. `X-Location-ID` always resolves against `public.locations`. Never a
   geofence. Nobody scopes HR to "the Delhi parking lot".
4. Any column named `location_id` **must** FK to `public.locations`.
   If a column references a geofence, it must be named `geofence_id`.
5. The header never overrides a subject's business rule.
   The header answers *"who can I see?"*
   The subject record answers *"what applies to them?"*
6. **Customers do not have a location.** A customer is company-scoped and
   can visit any branch. This is by design, not an omission.

---

## 2. Table → strategy map (frozen)

An empty cell (`—`) means **this table intentionally has no location column.
Do not add one "for consistency."** If you believe a `—` is wrong, open a PR
against this document first, then change the code.

### HR

| Table | Concept | Column |
|---|---|---|
| `company_employees` | Employment | `employment_location_id` |
| `company_employees` (UI default) | Request | `primary_location_id` |
| `employee_profiles` | derive via employee | — |
| `employee_documents` | derive via employee | — |
| `employee_department_history` | derive via employee | — |
| `employee_role_history` | derive via employee | — |
| `employee_exit` | derive via employee | — |
| `positions` | Resource (owned) | `location_id` (nullable, FK → `public.locations`) |

### Academics

| Table | Concept | Column |
|---|---|---|
| `academics.students` | Employment | `location_id` (NOT NULL, FK → `public.locations`) |
| `academics.teachers` | Employment | `location_id` (nullable for now — see changelog) |
| `academics.admissions` | derive via student | — |
| `academics.enrollments` | derive via student | — |
| `academics.student_guardians` | derive via student | — |
| `academics.student_documents` | derive via student | — |
| `academics.student_fee_invoices` | derive via student | — |
| `academics.student_fee_payments` | derive via student | — |
| `academics.fee_discounts` | derive via student | — |
| `academics.library_issues` | derive via student | — |
| `academics.student_transport_assignments` | derive via student | — |
| `academics.rooms` | Resource (owned) | — (rooms are identified by `room_code` + `company_id` today; may need location later) |
| `academics.sections` | company-scoped (see note) | — |
| `academics.courses`, `academics.subjects`, `academics.terms`, `academics.academic_year` | company catalog | — |
| `academics.exams`, `academics.exam_schedules`, `academics.exam_results` | derive via student/enrollment | — |
| `academics.assignments`, `academics.assignment_submissions` | derive via section/student | — |
| `academics.notifications` | company-scoped | — |
| All `analytics.*` | aggregated, no location | — |

**Note on `academics.sections`:** Sections are currently company-scoped.
This is correct when all students in a section are at the same campus (the
common case). If a future requirement calls for cross-campus sections, add
`sections.location_id` (nullable) at that time — see changelog.

### Sales

Everything in the `sales` schema is **company-scoped**. There is no location
dimension.

| Table | Concept | Column |
|---|---|---|
| `sales.customers` | company-scoped | — |
| `sales.sales_reps` | company-scoped | — |
| `sales.products` | company catalog | — |
| `sales.orders` | company-scoped (visit location is on the attendance event, not the order) | — |
| `sales.invoices`, `sales.payments`, `sales.returns`, `sales.credit_notes` | derive via order/customer | — |
| `sales.quotes`, `sales.promotions`, `sales.coupons`, `sales.automatic_discounts` | company catalog | — |
| All `sales_analytics.*` | aggregated, no location | — |

**Why:** Customers are not employees. They are not enrolled at a branch. They
buy from whichever location is convenient. Their interaction with a specific
branch is captured on the *transaction* (order/payment), not on the customer
record. If we ever need "which branch acquired this customer" for analytics,
add `acquisition_location_id` as nullable and information-only — it must
never be used for access control.

### Attendance

| Table | Concept | Column |
|---|---|---|
| `attendance.attendance_events` | Snapshot | `employment_location_id` **and** `geofence_id` |
| `attendance.attendance_daily_summary` | Snapshot | `employment_location_id` |
| `attendance.attendance_session_summary` | Snapshot | `employment_location_id` |
| `attendance.attendance_devices` | Geofence (owned) | `geofence_id` |
| `attendance.geofences` | Geofence | `employment_location_id` |
| `attendance.work_centers` | Resource (owned) | `location_id` (nullable) |
| `attendance.work_calendars` | Optional scope | `location_id` (nullable) |
| `attendance.schedule_templates` | Optional scope | `location_id` (nullable) |
| `attendance.schedule_instances` | Snapshot | `location_id` |
| `attendance.attendance_policies` | Optional scope | `location_id` (nullable) |
| `attendance.company_attendance_rules` | company only | — |
| `attendance.department_attendance_rules` | derive via department | — |
| `attendance.user_attendance_policies` | derive via subject | — |
| `attendance.attendance_sources` | company only | — |
| `attendance.attendance_exemptions` | derive via subject | — |
| `attendance.off_requests` | derive via employee | — |
| `attendance.user_off_entitlements` | derive via employee | — |
| `attendance.schedule_overrides` | derive via employee | — |
| `attendance.device_enrollments` | derive via device | — |
| `attendance.attendance_device_tokens` | derive via device | — |
| `attendance.attendance_device_heartbeats` | derive via device | — |
| `attendance.attendance_device_punch_batches` | derive via device | — |
| `attendance.attendance_device_punch_failures` | derive via device | — |
| `attendance.attendance_device_trust_history` | derive via device | — |

### Biometric

| Table | Concept | Column |
|---|---|---|
| `biometric.unified_face_embeddings` | derive via subject | — |
| `biometric.device_embedding_sync` | derive via device | — |

### Leave

| Table | Concept | Column |
|---|---|---|
| `leave.leave_policy` | Optional scope | `applies_to_location_id` (nullable) |
| `leave.leave_request` | derive via employee | — |
| `leave.leave_entitlement` | derive via employee | — |
| `leave.leave_balance_snapshot` | derive via employee | — |

### Payroll

| Table | Concept | Column |
|---|---|---|
| `payroll.payroll_run` | Optional scope | `location_id` (nullable) |
| `payroll.payroll_run_employees` | Snapshot | `employment_location_id` |
| `payroll.attendance_rule` | Optional scope | `location_id` (nullable) |
| `payroll.payroll_item` | derive via run | — |
| `payroll.payslip` | derive via run | — |
| `payroll.employee_salary` | derive via employee | — |
| `payroll.employee_bank_details` | derive via employee | — |

### Access / RBAC

| Table | Concept | Column |
|---|---|---|
| `employee_location_access` | Access | `location_id` (FK → `public.locations`) |
| `employee_location_history` | Employment (audit) | `location_id` (FK → `public.locations`) |
| `rbac.*` | company only | — |

---

## 3. Index rule

Every index on a business table **starts with `company_id`**. Location-scoped
indexes are always `(company_id, <location_column>, ...)` in that order.

`company_id` is the tenant boundary. Every business query filters by it.
Location is a secondary filter inside a tenant.

Canonical shapes:

    (company_id, employment_location_id, user_id)
    (company_id, location_id, event_time DESC)
    (company_id, geofence_id, event_time DESC)
    (company_id, location_id, period_start DESC)
    (company_id, location_id)  -- academics.students

---

## 4. Repository pattern

Every location-aware `List` / `Search` / `Count` method takes:

    func ListX(ctx, companyID uuid.UUID, locationID *uuid.UUID, ...)

`nil` means "no location filter" (company-wide, only permitted when the
request context is `ALL` or the route is not location-scoped).

SQL clause — one line, no dynamic SQL:

    AND ($N::uuid IS NULL OR <location_column> = $N)

The index does the work.

---

## 5. Context helper

Handlers read location from context via `locationctx.FromContext(ctx)`.

- Returns `Context{Mode, LocationID, AccessLevel}`.
- Returns `ErrLocationContextMissing` if the route is not wrapped by
  `LocationValidationMiddleware`. Handlers must return **500**, never fall
  back to a company-wide read.

`locationctx.Filter(ctx)` is the sanctioned accessor for reads. It panics on
missing context because that is a wiring bug, not a legitimate case.

---

## 6. Subject location resolver

Attendance events are stamped with the subject's location at write time.
This is done by a `SubjectLocationResolver`:

| Subject type | Location source |
|---|---|
| `employee` | `company_employees.employment_location_id` |
| `student` | `academics.students.location_id` |
| `customer` | none — returns `(nil, nil)` |

Customers have no location. Their attendance events are stamped with the
**visit location** — derived from the device's geofence, the admin's
`X-Location-ID`, or GPS. Never from the customer record.

See `internal/attendance/service/resolver/` for the implementation.

---

## 7. Migration plan (updated)

| # | Migration | Status |
|---|---|---|
| 1 | Rename `attendance.attendance_locations` → `attendance.geofences` | ✅ Done |
| 2 | Add `geofences.employment_location_id` + FK + backfill | ✅ Done |
| 3 | Rename `attendance_devices.location_id` → `geofence_id` + FK | ✅ Done |
| 4 | Add `attendance_events.employment_location_id` + `geofence_id` + FKs | ✅ Done |
| 5 | Add `attendance_daily_summary.employment_location_id` + FK | ✅ Done |
| 6 | Add `attendance_session_summary.employment_location_id` + FK | ✅ Done |
| 7 | Add `company_employees.employment_location_id` + FK | ✅ Done |
| 8 | Add nullable location scopes on work_centers / work_calendars / schedule_templates / schedule_instances / attendance_policies | ✅ Done |
| 9 | Add `payroll_run.location_id`, `attendance_rule.location_id` | ✅ Done |
| 10 | Add `leave_policy.applies_to_location_id` + update effective-policy function | ✅ Done |
| 11 | Add `payroll_run_employees` snapshot table | ✅ Done |
| 12 | **Add `academics.students.location_id` (NOT NULL, FK) + index** | ✅ Done |
| 13 | Add `academics.teachers.location_id` (nullable, FK) — *future* | ⏳ Pending |
| 14 | Add `academics.sections.location_id` (nullable, FK) — *only if cross-campus sections are needed* | ⏳ Deferred |

---

## 8. What is deliberately NOT location-scoped

Two categories. Adding a location column to either would be a mistake.

### Customers

`sales.customers` has no `location_id`. A customer is company-scoped.
Adding a mandatory location would force every customer to belong to one
branch, breaking the natural business model (Apollo Ynr customer buying from
Apollo Delhi).

If per-branch acquisition analytics are ever needed, add
`acquisition_location_id` as **nullable** and **information-only**. It must
never be used for authorization or filtering.

### Sales transactions

`sales.orders`, `sales.invoices`, `sales.payments` — all company-scoped.
The *branch where a transaction happened* is a data point to record on the
transaction itself, not a scope filter on the customer. If this becomes a
requirement, add `sales.orders.location_id` as a nullable information
column, separate from this architecture's scope model.

---

## 9. Changelog

| Date | Change | Reason |
|---|---|---|
| 2026-09-14 | Initial version | Establish single source of truth |
| 2026-09-15 | Added Academics and Sales sections. Students have a mandatory `location_id`. Customers and sales transactions explicitly have no location column. | Clarify scope for education and commerce domains |