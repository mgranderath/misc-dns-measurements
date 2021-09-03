package db

import "gorm.io/gorm"

type FastOpenSupport struct {
	gorm.Model
	IP string
	Port int
	Support bool
}

type Certificate struct {
	gorm.Model
	Protocol string
	Port int
	IP string
	Raw []byte
}

type EDNS0 struct {
	gorm.Model
	IP string
	Support bool
	Timeout *uint16
}

type Q0RTTSupport struct {
	gorm.Model
	IP string
	Port int
	Support bool
}

type QVersion struct {
	gorm.Model
	IP string
	Port int
	QVersion uint64
	DraftVersion string
}