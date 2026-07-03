package models

// Subject types
const (
	SubjectTypeEmployee = "employee"
	SubjectTypeStudent  = "student"
	SubjectTypeCustomer = "customer"
)

// Attendance statuses (reuse from HR)
const (
	StatusPresent      = "present"
	StatusAbsent       = "absent"
	StatusLate         = "late"
	StatusHalfDay      = "half_day"
	StatusLeavePaid    = "leave"
	StatusLeaveUnpaid  = "leave_unpaid"
	StatusHoliday      = "holiday"
	StatusWeeklyOff    = "weekly_off"
	StatusNotScheduled = "not_scheduled"
	StatusExcused      = "excused" // 👈 ADD THIS

)
