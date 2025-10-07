package util

import (
    "log"
    "os"
)

var Logger = log.New(os.Stdout, "[AUTH-SERVICE] ", log.LstdFlags|log.Lshortfile)
