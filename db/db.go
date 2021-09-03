package db

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"log"
)

var db *gorm.DB

func init() {
	dbOpen, err := gorm.Open(sqlite.Open("sqlite.db?cache=shared&mode=rwc&_journal_mode=WAL"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db = dbOpen

	db.AutoMigrate(&FastOpenSupport{})
	db.AutoMigrate(&Certificate{})
	db.AutoMigrate(&EDNS0{})
	db.AutoMigrate(&Q0RTTSupport{})
	db.AutoMigrate(&QVersion{})
}

func AddFastOpenRecord(ip string, port int, supports bool) {
	db.Create(&FastOpenSupport{
		IP:      ip,
		Port: port,
		Support: supports,
	})
}

func Add0RTTRecord(ip string, port int, supports bool) {
	db.Create(&Q0RTTSupport{
		IP: ip,
		Port: port,
		Support: supports,
	})
}

func AddCertificate(ip string, protocol string, port int, certificate []byte) {
	db.Create(&Certificate{IP: ip, Raw: certificate, Port: port, Protocol: protocol})
}

func AddEDNS0(ip string, supports bool, timeout *uint16) {
	db.Create(&EDNS0{IP: ip, Support: supports, Timeout: timeout})
}

func AddQVersion(ip string, port int, qversion uint64, draftVersion string) {
	db.Create(&QVersion{IP: ip, Port: port, QVersion: qversion, DraftVersion: draftVersion})
}

func Close() {
	rawDB, err := db.DB()
	if err != nil {
		log.Fatal(err)
	}
	rawDB.Close()
}