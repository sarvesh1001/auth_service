package constants

// CountryDefaultTimezone maps ISO-3166 alpha-2 country codes to the most
// common tz for that country.
//
// This is a HINT for onboarding: when a company signs up with data_region
// "IN", we pre-fill the picker with "Asia/Kolkata". Admin can override.
//
// For countries with multiple zones (see CountriesWithMultipleTimezones),
// the value here is the most-populous zone (usually the capital's zone).
var CountryDefaultTimezone = map[string]string{
	// South Asia
	"IN": "Asia/Kolkata",
	"PK": "Asia/Karachi",
	"BD": "Asia/Dhaka",
	"LK": "Asia/Colombo",
	"NP": "Asia/Kathmandu",
	"AF": "Asia/Kabul",
	"MV": "Indian/Maldives",
	"BT": "Asia/Thimphu",

	// Middle East
	"AE": "Asia/Dubai",
	"SA": "Asia/Riyadh",
	"QA": "Asia/Qatar",
	"KW": "Asia/Kuwait",
	"BH": "Asia/Bahrain",
	"OM": "Asia/Muscat",
	"YE": "Asia/Aden",
	"IQ": "Asia/Baghdad",
	"IR": "Asia/Tehran",
	"IL": "Asia/Jerusalem",
	"JO": "Asia/Amman",
	"LB": "Asia/Beirut",
	"SY": "Asia/Damascus",
	"TR": "Europe/Istanbul",

	// Southeast Asia
	"SG": "Asia/Singapore",
	"MY": "Asia/Kuala_Lumpur",
	"TH": "Asia/Bangkok",
	"VN": "Asia/Ho_Chi_Minh",
	"PH": "Asia/Manila",
	"ID": "Asia/Jakarta",
	"BN": "Asia/Brunei",
	"MM": "Asia/Yangon",
	"KH": "Asia/Phnom_Penh",
	"LA": "Asia/Vientiane",

	// East Asia
	"CN": "Asia/Shanghai",
	"HK": "Asia/Hong_Kong",
	"TW": "Asia/Taipei",
	"JP": "Asia/Tokyo",
	"KR": "Asia/Seoul",
	"KP": "Asia/Pyongyang",
	"MN": "Asia/Ulaanbaatar",

	// Central Asia
	"KZ": "Asia/Almaty",
	"UZ": "Asia/Tashkent",
	"KG": "Asia/Bishkek",
	"TJ": "Asia/Dushanbe",
	"TM": "Asia/Ashgabat",

	// Europe
	"GB": "Europe/London",
	"IE": "Europe/Dublin",
	"FR": "Europe/Paris",
	"DE": "Europe/Berlin",
	"IT": "Europe/Rome",
	"ES": "Europe/Madrid",
	"PT": "Europe/Lisbon",
	"NL": "Europe/Amsterdam",
	"BE": "Europe/Brussels",
	"CH": "Europe/Zurich",
	"AT": "Europe/Vienna",
	"SE": "Europe/Stockholm",
	"NO": "Europe/Oslo",
	"DK": "Europe/Copenhagen",
	"FI": "Europe/Helsinki",
	"PL": "Europe/Warsaw",
	"CZ": "Europe/Prague",
	"HU": "Europe/Budapest",
	"RO": "Europe/Bucharest",
	"BG": "Europe/Sofia",
	"GR": "Europe/Athens",
	"RU": "Europe/Moscow",
	"UA": "Europe/Kiev",
	"BY": "Europe/Minsk",
	"LV": "Europe/Riga",
	"LT": "Europe/Vilnius",
	"EE": "Europe/Tallinn",
	"MD": "Europe/Chisinau",

	// Africa
	"ZA": "Africa/Johannesburg",
	"EG": "Africa/Cairo",
	"NG": "Africa/Lagos",
	"KE": "Africa/Nairobi",
	"MA": "Africa/Casablanca",
	"DZ": "Africa/Algiers",
	"TN": "Africa/Tunis",
	"LY": "Africa/Tripoli",
	"ET": "Africa/Addis_Ababa",
	"TZ": "Africa/Dar_es_Salaam",
	"UG": "Africa/Kampala",
	"GH": "Africa/Accra",
	"MZ": "Africa/Maputo",
	"ZW": "Africa/Harare",
	"ZM": "Africa/Lusaka",
	"SD": "Africa/Khartoum",
	"CD": "Africa/Kinshasa",
	"CM": "Africa/Douala",
	"CI": "Africa/Abidjan",
	"SN": "Africa/Dakar",

	// Americas
	"US": "America/New_York",
	"CA": "America/Toronto",
	"MX": "America/Mexico_City",
	"BR": "America/Sao_Paulo",
	"AR": "America/Buenos_Aires",
	"CL": "America/Santiago",
	"CO": "America/Bogota",
	"PE": "America/Lima",
	"VE": "America/Caracas",
	"EC": "America/Guayaquil",
	"BO": "America/La_Paz",
	"PY": "America/Asuncion",
	"UY": "America/Montevideo",
	"GY": "America/Guyana",
	"SR": "America/Paramaribo",
	"PA": "America/Panama",
	"CR": "America/Costa_Rica",
	"GT": "America/Guatemala",
	"SV": "America/El_Salvador",
	"HN": "America/Tegucigalpa",
	"NI": "America/Managua",
	"CU": "America/Havana",
	"DO": "America/Santo_Domingo",
	"JM": "America/Jamaica",
	"TT": "America/Port_of_Spain",
	"BS": "America/Nassau",
	"BB": "America/Barbados",
	"PR": "America/Puerto_Rico",

	// Oceania / Pacific
	"AU": "Australia/Sydney",
	"NZ": "Pacific/Auckland",
	"FJ": "Pacific/Fiji",
	"PG": "Pacific/Port_Moresby",
	"NC": "Pacific/Noumea",
	"PF": "Pacific/Tahiti",
	"WS": "Pacific/Apia",
	"TO": "Pacific/Tongatapu",
	"VU": "Pacific/Efate",
	"SB": "Pacific/Guadalcanal",
	"GU": "Pacific/Guam",
	"KI": "Pacific/Tarawa",
	"MH": "Pacific/Majuro",
	"FM": "Pacific/Pohnpei",
	"PW": "Pacific/Palau",
	"NR": "Pacific/Nauru",
	"TV": "Pacific/Funafuti",
	"CK": "Pacific/Rarotonga",

	// Atlantic / Caribbean
	"IS": "Atlantic/Reykjavik",
	"CV": "Atlantic/Cape_Verde",
	"GL": "America/Godthab",
	"FO": "Atlantic/Faroe",
}

// CountriesWithMultipleTimezones flags countries where a single default
// is insufficient. When a company signs up with one of these and does not
// pick a specific tz, the UI should prompt the admin to confirm.
var CountriesWithMultipleTimezones = map[string]bool{
	"US": true,  // 6 zones (Pacific, Mountain, Central, Eastern, Alaska, Hawaii)
	"CA": true,  // 6 zones
	"AU": true,  // 5 zones (AWST, ACST, AEST, +2 DST variants, Lord Howe)
	"RU": true,  // 11 zones
	"BR": true,  // 4 zones
	"MX": true,  // 4 zones
	"ID": true,  // 3 zones (WIB, WITA, WIT)
	"KZ": true,  // 2 zones
	"CN": false, // officially 1 zone (Beijing time), despite geographic spread
	"IN": false, // officially 1 zone (IST), though Andaman uses same
	"NZ": true,  // 2 zones (NZ + Chatham)
	"CL": true,  // 2 zones (mainland + Easter Island)
	"EC": true,  // 2 zones (mainland + Galapagos)
	"ES": true,  // 2 zones (mainland + Canary Islands)
	"PT": true,  // 2 zones (mainland + Azores)
	"UA": false, // officially 1 zone since 2022
	"MY": false, // 1 zone since 1982
	"SG": false,
	"ZA": false,
	"EG": false,
}
