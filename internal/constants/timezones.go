package constants

// ─────────────────────────────────────────────────────────────────────
// TIMEZONE DATA
//
// This file is the single source of truth for which IANA timezones are
// considered "supported" by the platform.
//
// OFFSETS ARE HINTS.
// The standard and DST offsets listed below are for UI display
// ("Asia/Kolkata — UTC+05:30") and onboarding suggestions. They are NOT
// used for any date math. Always compute the live offset with:
//
//     _, offsetSeconds := time.Now().In(loc).Zone()
//
// Because DST rules change (Iran abolished DST in 2022, Mexico in 2022,
// Brazil in 2019), the hint can drift. The `time` package's embedded
// tzdata (`import _ "time/tzdata"`) is the runtime source of truth.
//
// Offset units: minutes. -720 = UTC−12:00, +840 = UTC+14:00.
// ─────────────────────────────────────────────────────────────────────

// Timezone is one row in the supported-zones table.
type Timezone struct {
	// IANA name. This is what gets stored in the DB.
	Name string

	// Continent-level grouping for UI dropdowns.
	Region string

	// Standard (non-DST) offset in minutes from UTC.
	// e.g. IST = 330 for +05:30, EST = -300 for −05:00.
	StdOffsetMin int

	// DST offset in minutes. Set equal to StdOffsetMin for zones that
	// do not observe DST.
	DstOffsetMin int

	// Freeform note. Shown as a subtitle in the picker when useful.
	Note string
}

// Regions used for UI grouping.
const (
	RegionUTC      = "UTC"
	RegionAmericas = "Americas"
	RegionEurope   = "Europe"
	RegionAfrica   = "Africa"
	RegionAsia     = "Asia"
	RegionOceania  = "Oceania"
	RegionAtlantic = "Atlantic"
	RegionIndian   = "Indian"
	RegionPacific  = "Pacific"
)

// AllTimezones is the canonical list of supported IANA zones.
//
// Curated to ~120 zones covering 99.9% of B2B users. Deliberately
// excludes tiny or historical zones (Pacific/Johnston, Antarctica/*).
// Add more only if a customer asks.
//
// Ordering: by region, then east to west within region.
var AllTimezones = []Timezone{
	// ── UTC ─────────────────────────────────────────────────────────
	{RegionUTC, "UTC", 0, 0, "Coordinated Universal Time"},

	// ── Pacific / Oceania (west of line, east of line) ──────────────
	{RegionPacific, "Pacific/Kiritimati", 840, 840, "UTC+14:00 (Line Islands)"},
	{RegionPacific, "Pacific/Apia", 780, 840, "UTC+13:00 (Samoa, DST +14:00)"},
	{RegionPacific, "Pacific/Tongatapu", 780, 780, "UTC+13:00 (Tonga)"},
	{RegionPacific, "Pacific/Auckland", 720, 780, "NZST (DST NZDT +13:00)"},
	{RegionPacific, "Pacific/Chatham", 765, 825, "CHAST (45-min base, DST +13:45)"},
	{RegionPacific, "Pacific/Fiji", 720, 780, "FJT (DST suspended since 2022)"},
	{RegionPacific, "Pacific/Norfolk", 660, 720, "NFT (DST +12:00)"},
	{RegionPacific, "Pacific/Noumea", 660, 660, "NCT (New Caledonia)"},
	{RegionPacific, "Pacific/Guadalcanal", 660, 660, "SBT (Solomon Islands)"},
	{RegionPacific, "Pacific/Efate", 660, 660, "VUT (Vanuatu)"},
	{RegionPacific, "Pacific/Bougainville", 660, 660, "BST (Bougainville)"},
	{RegionPacific, "Pacific/Majuro", 720, 720, "MHT (Marshall Islands)"},
	{RegionPacific, "Pacific/Tarawa", 720, 720, "GILT (Kiribati)"},
	{RegionPacific, "Pacific/Wake", 720, 720, "WAKT"},
	{RegionPacific, "Pacific/Guam", 600, 600, "ChST"},
	{RegionPacific, "Pacific/Port_Moresby", 600, 600, "PGT"},
	{RegionPacific, "Pacific/Saipan", 600, 600, "ChST"},
	{RegionPacific, "Pacific/Nauru", 720, 720, "NRT"},
	{RegionPacific, "Pacific/Palau", 540, 540, "PWT"},
	{RegionPacific, "Pacific/Midway", -660, -660, "SST"},
	{RegionPacific, "Pacific/Honolulu", -600, -600, "HST (no DST)"},
	{RegionPacific, "Pacific/Marquesas", -570, -570, "MART (−09:30)"},
	{RegionPacific, "Pacific/Gambier", -540, -540, "GAMT"},
	{RegionPacific, "Pacific/Pitcairn", -480, -480, "PST (no DST)"},
	{RegionPacific, "Pacific/Easter", -360, -300, "EAST (DST −05:00)"},

	// ── Americas ────────────────────────────────────────────────────
	{RegionAmericas, "America/St_Johns", -210, -150, "NST (−03:30, DST −02:30)"},
	{RegionAmericas, "America/Halifax", -240, -180, "AST (DST ADT −03:00)"},
	{RegionAmericas, "America/Puerto_Rico", -240, -240, "AST (no DST)"},
	{RegionAmericas, "America/Santo_Domingo", -240, -240, "AST (no DST)"},
	{RegionAmericas, "America/Santiago", -240, -180, "CLT (DST CLST −03:00)"},
	{RegionAmericas, "America/Asuncion", -240, -180, "PYT (DST −03:00)"},
	{RegionAmericas, "America/Caracas", -240, -240, "VET (no DST)"},
	{RegionAmericas, "America/La_Paz", -240, -240, "BOT (no DST)"},
	{RegionAmericas, "America/Manaus", -240, -240, "AMT (no DST)"},
	{RegionAmericas, "America/Cuiaba", -240, -240, "AMT (no DST)"},
	{RegionAmericas, "America/Sao_Paulo", -180, -180, "BRT (no DST since 2019)"},
	{RegionAmericas, "America/Buenos_Aires", -180, -180, "ART (no DST)"},
	{RegionAmericas, "America/Montevideo", -180, -180, "UYT (no DST)"},
	{RegionAmericas, "America/Cayenne", -180, -180, "GFT"},
	{RegionAmericas, "America/Recife", -180, -180, "BRT (no DST)"},
	{RegionAmericas, "America/Fortaleza", -180, -180, "BRT (no DST)"},
	{RegionAmericas, "America/Noronha", -120, -120, "FNT (Fernando de Noronha)"},
	{RegionAmericas, "America/Godthab", -180, -120, "WGT (DST −02:00)"},
	{RegionAmericas, "America/Danmarkshavn", 0, 0, "GMT (no DST)"},
	{RegionAmericas, "America/New_York", -300, -240, "EST (DST EDT −04:00)"},
	{RegionAmericas, "America/Toronto", -300, -240, "EST (DST EDT)"},
	{RegionAmericas, "America/Detroit", -300, -240, "EST (DST EDT)"},
	{RegionAmericas, "America/Indianapolis", -300, -240, "EST (DST EDT)"},
	{RegionAmericas, "America/Havana", -300, -240, "CST (Cuba DST)"},
	{RegionAmericas, "America/Nassau", -300, -240, "EST (DST EDT)"},
	{RegionAmericas, "America/Bogota", -300, -300, "COT (no DST)"},
	{RegionAmericas, "America/Lima", -300, -300, "PET (no DST)"},
	{RegionAmericas, "America/Panama", -300, -300, "EST (no DST)"},
	{RegionAmericas, "America/Jamaica", -300, -300, "EST (no DST)"},
	{RegionAmericas, "America/Guayaquil", -300, -300, "ECT (no DST)"},
	{RegionAmericas, "America/Chicago", -360, -300, "CST (DST CDT −05:00)"},
	{RegionAmericas, "America/Winnipeg", -360, -300, "CST (DST CDT)"},
	{RegionAmericas, "America/Mexico_City", -360, -360, "CST (no DST since 2022)"},
	{RegionAmericas, "America/Monterrey", -360, -360, "CST (no DST)"},
	{RegionAmericas, "America/Guatemala", -360, -360, "CST (no DST)"},
	{RegionAmericas, "America/Costa_Rica", -360, -360, "CST (no DST)"},
	{RegionAmericas, "America/El_Salvador", -360, -360, "CST (no DST)"},
	{RegionAmericas, "America/Tegucigalpa", -360, -360, "CST (no DST)"},
	{RegionAmericas, "America/Managua", -360, -360, "CST (no DST)"},
	{RegionAmericas, "America/Regina", -360, -360, "CST (no DST)"},
	{RegionAmericas, "America/Denver", -420, -360, "MST (DST MDT −06:00)"},
	{RegionAmericas, "America/Edmonton", -420, -360, "MST (DST MDT)"},
	{RegionAmericas, "America/Boise", -420, -360, "MST (DST MDT)"},
	{RegionAmericas, "America/Phoenix", -420, -420, "MST (no DST — Arizona)"},
	{RegionAmericas, "America/Chihuahua", -420, -360, "MST (DST MDT)"},
	{RegionAmericas, "America/Mazatlan", -420, -420, "MST (no DST)"},
	{RegionAmericas, "America/Hermosillo", -420, -420, "MST (no DST)"},
	{RegionAmericas, "America/Los_Angeles", -480, -420, "PST (DST PDT −07:00)"},
	{RegionAmericas, "America/Vancouver", -480, -420, "PST (DST PDT)"},
	{RegionAmericas, "America/Tijuana", -480, -420, "PST (DST PDT)"},
	{RegionAmericas, "America/Anchorage", -540, -480, "AKST (DST AKDT −08:00)"},
	{RegionAmericas, "America/Juneau", -540, -480, "AKST (DST AKDT)"},
	{RegionAmericas, "America/Adak", -600, -540, "HST (DST HDT −09:00)"},
	{RegionAmericas, "America/Whitehorse", -420, -420, "MST (permanent, since 2020)"},

	// ── Atlantic ────────────────────────────────────────────────────
	{RegionAtlantic, "Atlantic/Azores", -60, 0, "AZOT (DST UTC+00:00)"},
	{RegionAtlantic, "Atlantic/Cape_Verde", -60, -60, "CVT (no DST)"},
	{RegionAtlantic, "Atlantic/Reykjavik", 0, 0, "GMT (no DST)"},
	{RegionAtlantic, "Atlantic/Canary", 0, 60, "WET (DST WEST +01:00)"},
	{RegionAtlantic, "Atlantic/Madeira", 0, 60, "WET (DST +01:00)"},
	{RegionAtlantic, "Atlantic/Faroe", 0, 60, "WET (DST +01:00)"},
	{RegionAtlantic, "Atlantic/Stanley", -180, -180, "FKST (no DST since 2011)"},
	{RegionAtlantic, "Atlantic/South_Georgia", -120, -120, "GST (no DST)"},

	// ── Europe ──────────────────────────────────────────────────────
	{RegionEurope, "Europe/London", 0, 60, "GMT (DST BST +01:00)"},
	{RegionEurope, "Europe/Dublin", 0, 60, "IST is GMT in winter, DST +01:00"},
	{RegionEurope, "Europe/Lisbon", 0, 60, "WET (DST WEST +01:00)"},
	{RegionEurope, "Europe/Berlin", 60, 120, "CET (DST CEST +02:00)"},
	{RegionEurope, "Europe/Paris", 60, 120, "CET (DST CEST)"},
	{RegionEurope, "Europe/Madrid", 60, 120, "CET (DST CEST)"},
	{RegionEurope, "Europe/Rome", 60, 120, "CET (DST CEST)"},
	{RegionEurope, "Europe/Amsterdam", 60, 120, "CET (DST CEST)"},
	{RegionEurope, "Europe/Brussels", 60, 120, "CET (DST CEST)"},
	{RegionEurope, "Europe/Vienna", 60, 120, "CET (DST CEST)"},
	{RegionEurope, "Europe/Zurich", 60, 120, "CET (DST CEST)"},
	{RegionEurope, "Europe/Prague", 60, 120, "CET (DST CEST)"},
	{RegionEurope, "Europe/Warsaw", 60, 120, "CET (DST CEST)"},
	{RegionEurope, "Europe/Budapest", 60, 120, "CET (DST CEST)"},
	{RegionEurope, "Europe/Stockholm", 60, 120, "CET (DST CEST)"},
	{RegionEurope, "Europe/Oslo", 60, 120, "CET (DST CEST)"},
	{RegionEurope, "Europe/Copenhagen", 60, 120, "CET (DST CEST)"},
	{RegionEurope, "Europe/Helsinki", 120, 180, "EET (DST EEST +03:00)"},
	{RegionEurope, "Europe/Athens", 120, 180, "EET (DST EEST)"},
	{RegionEurope, "Europe/Bucharest", 120, 180, "EET (DST EEST)"},
	{RegionEurope, "Europe/Sofia", 120, 180, "EET (DST EEST)"},
	{RegionEurope, "Europe/Kiev", 120, 180, "EET (DST EEST)"},
	{RegionEurope, "Europe/Riga", 120, 180, "EET (DST EEST)"},
	{RegionEurope, "Europe/Vilnius", 120, 180, "EET (DST EEST)"},
	{RegionEurope, "Europe/Tallinn", 120, 180, "EET (DST EEST)"},
	{RegionEurope, "Europe/Chisinau", 120, 180, "EET (DST EEST)"},
	{RegionEurope, "Europe/Moscow", 180, 180, "MSK (no DST since 2014)"},
	{RegionEurope, "Europe/Istanbul", 180, 180, "TRT (no DST since 2016)"},
	{RegionEurope, "Europe/Minsk", 180, 180, "MSK (no DST)"},

	// ── Africa ──────────────────────────────────────────────────────
	{RegionAfrica, "Africa/Casablanca", 60, 60, "WEST (Ramadan adjusts to UTC+00:00)"},
	{RegionAfrica, "Africa/El_Aaiun", 60, 60, "WEST (Ramadan adjusts)"},
	{RegionAfrica, "Africa/Algiers", 60, 60, "CET (no DST)"},
	{RegionAfrica, "Africa/Tunis", 60, 60, "CET (no DST)"},
	{RegionAfrica, "Africa/Lagos", 60, 60, "WAT (no DST)"},
	{RegionAfrica, "Africa/Kinshasa", 60, 60, "WAT (no DST)"},
	{RegionAfrica, "Africa/Libreville", 60, 60, "WAT (no DST)"},
	{RegionAfrica, "Africa/Cairo", 120, 180, "EET (DST reintroduced 2023)"},
	{RegionAfrica, "Africa/Johannesburg", 120, 120, "SAST (no DST)"},
	{RegionAfrica, "Africa/Maputo", 120, 120, "CAT (no DST)"},
	{RegionAfrica, "Africa/Harare", 120, 120, "CAT (no DST)"},
	{RegionAfrica, "Africa/Lusaka", 120, 120, "CAT (no DST)"},
	{RegionAfrica, "Africa/Khartoum", 120, 120, "CAT (no DST)"},
	{RegionAfrica, "Africa/Tripoli", 120, 120, "EET (no DST)"},
	{RegionAfrica, "Africa/Nairobi", 180, 180, "EAT (no DST)"},
	{RegionAfrica, "Africa/Addis_Ababa", 180, 180, "EAT (no DST)"},
	{RegionAfrica, "Africa/Dar_es_Salaam", 180, 180, "EAT (no DST)"},
	{RegionAfrica, "Africa/Kampala", 180, 180, "EAT (no DST)"},

	// ── Indian Ocean ────────────────────────────────────────────────
	{RegionIndian, "Indian/Antananarivo", 180, 180, "EAT (no DST)"},
	{RegionIndian, "Indian/Mayotte", 180, 180, "EAT (no DST)"},
	{RegionIndian, "Indian/Reunion", 240, 240, "RET (no DST)"},
	{RegionIndian, "Indian/Mauritius", 240, 240, "MUT (no DST)"},
	{RegionIndian, "Indian/Maldives", 300, 300, "MVT (no DST)"},
	{RegionIndian, "Indian/Kerguelen", 300, 300, "TFT (no DST)"},
	{RegionIndian, "Indian/Chagos", 360, 360, "IOT (no DST)"},
	{RegionIndian, "Indian/Cocos", 390, 390, "CCT (+06:30)"},
	{RegionIndian, "Indian/Christmas", 420, 420, "CXT (no DST)"},

	// ── Asia ────────────────────────────────────────────────────────
	{RegionAsia, "Asia/Jerusalem", 120, 180, "IST Israel (DST IDT +03:00)"},
	{RegionAsia, "Asia/Beirut", 120, 180, "EET (DST EEST)"},
	{RegionAsia, "Asia/Damascus", 180, 180, "AST (no DST since 2022)"},
	{RegionAsia, "Asia/Amman", 180, 180, "AST (permanent +03:00 since 2022)"},
	{RegionAsia, "Asia/Riyadh", 180, 180, "AST (no DST)"},
	{RegionAsia, "Asia/Kuwait", 180, 180, "AST (no DST)"},
	{RegionAsia, "Asia/Qatar", 180, 180, "AST (no DST)"},
	{RegionAsia, "Asia/Bahrain", 180, 180, "AST (no DST)"},
	{RegionAsia, "Asia/Baghdad", 180, 180, "AST (no DST)"},
	{RegionAsia, "Asia/Aden", 180, 180, "AST (no DST)"},
	{RegionAsia, "Asia/Tehran", 210, 210, "IRST (DST abolished 2022)"},
	{RegionAsia, "Asia/Dubai", 240, 240, "GST (no DST)"},
	{RegionAsia, "Asia/Muscat", 240, 240, "GST (no DST)"},
	{RegionAsia, "Asia/Baku", 240, 240, "AZT (no DST since 2016)"},
	{RegionAsia, "Asia/Tbilisi", 240, 240, "GET (no DST)"},
	{RegionAsia, "Asia/Yerevan", 240, 240, "AMT (no DST)"},
	{RegionAsia, "Asia/Kabul", 270, 270, "AFT (+04:30, no DST)"},
	{RegionAsia, "Asia/Karachi", 300, 300, "PKT (no DST since 2009)"},
	{RegionAsia, "Asia/Tashkent", 300, 300, "UZT (no DST)"},
	{RegionAsia, "Asia/Dushanbe", 300, 300, "TJT (no DST)"},
	{RegionAsia, "Asia/Ashgabat", 300, 300, "TMT (no DST)"},
	{RegionAsia, "Asia/Kolkata", 330, 330, "IST (+05:30, no DST)"},
	{RegionAsia, "Asia/Colombo", 330, 330, "IST (+05:30, no DST)"},
	{RegionAsia, "Asia/Kathmandu", 345, 345, "NPT (+05:45, no DST)"},
	{RegionAsia, "Asia/Dhaka", 360, 360, "BST (no DST since 2010)"},
	{RegionAsia, "Asia/Almaty", 360, 360, "ALMT (no DST since 2005)"},
	{RegionAsia, "Asia/Bishkek", 360, 360, "KGT (no DST)"},
	{RegionAsia, "Asia/Yangon", 390, 390, "MMT (+06:30, no DST)"},
	{RegionAsia, "Asia/Bangkok", 420, 420, "ICT (no DST)"},
	{RegionAsia, "Asia/Jakarta", 420, 420, "WIB (no DST)"},
	{RegionAsia, "Asia/Ho_Chi_Minh", 420, 420, "ICT (no DST)"},
	{RegionAsia, "Asia/Phnom_Penh", 420, 420, "ICT (no DST)"},
	{RegionAsia, "Asia/Vientiane", 420, 420, "ICT (no DST)"},
	{RegionAsia, "Asia/Shanghai", 480, 480, "CST (China, no DST)"},
	{RegionAsia, "Asia/Hong_Kong", 480, 480, "HKT (no DST)"},
	{RegionAsia, "Asia/Taipei", 480, 480, "CST (no DST)"},
	{RegionAsia, "Asia/Singapore", 480, 480, "SGT (no DST)"},
	{RegionAsia, "Asia/Kuala_Lumpur", 480, 480, "MYT (no DST)"},
	{RegionAsia, "Asia/Manila", 480, 480, "PST (no DST)"},
	{RegionAsia, "Asia/Makassar", 480, 480, "WITA (no DST)"},
	{RegionAsia, "Asia/Brunei", 480, 480, "BNT (no DST)"},
	{RegionAsia, "Asia/Ulaanbaatar", 480, 480, "ULAT (no DST since 2017)"},
	{RegionAsia, "Asia/Tokyo", 540, 540, "JST (no DST)"},
	{RegionAsia, "Asia/Seoul", 540, 540, "KST (no DST)"},
	{RegionAsia, "Asia/Pyongyang", 540, 540, "KST (no DST)"},
	{RegionAsia, "Asia/Vladivostok", 600, 600, "VLAT (no DST)"},
	{RegionAsia, "Asia/Magadan", 660, 660, "MAGT (no DST)"},
	{RegionAsia, "Asia/Sakhalin", 660, 660, "SAKT (no DST)"},
	{RegionAsia, "Asia/Kamchatka", 720, 720, "PETT (no DST)"},
	{RegionAsia, "Asia/Anadyr", 720, 720, "ANAT (no DST)"},

	// ── Australia (still under Pacific region semantically) ─────────
	{RegionOceania, "Australia/Perth", 480, 480, "AWST (no DST)"},
	{RegionOceania, "Australia/Eucla", 525, 525, "ACWST (+08:45, no DST)"},
	{RegionOceania, "Australia/Darwin", 570, 570, "ACST (no DST)"},
	{RegionOceania, "Australia/Adelaide", 570, 630, "ACST (DST ACDT +10:30)"},
	{RegionOceania, "Australia/Brisbane", 600, 600, "AEST (no DST)"},
	{RegionOceania, "Australia/Sydney", 600, 660, "AEST (DST AEDT +11:00)"},
	{RegionOceania, "Australia/Melbourne", 600, 660, "AEST (DST AEDT)"},
	{RegionOceania, "Australia/Hobart", 600, 660, "AEST (DST AEDT)"},
	{RegionOceania, "Australia/Lord_Howe", 630, 660, "LHST (30-min DST, unique)"},
}

// TimezonesByRegion groups AllTimezones by region for UI dropdowns.
var TimezonesByRegion = func() map[string][]Timezone {
	m := make(map[string][]Timezone)
	for _, tz := range AllTimezones {
		m[tz.Region] = append(m[tz.Region], tz)
	}
	return m
}()

// AllTimezoneNames is a flat slice of IANA names. Fast membership testing.
var AllTimezoneNames = func() []string {
	names := make([]string, 0, len(AllTimezones))
	for _, tz := range AllTimezones {
		names = append(names, tz.Name)
	}
	return names
}()
