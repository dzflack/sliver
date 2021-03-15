package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

// Certificate - Certificate database model
type Certificate struct {
	// gorm.Model

	ID             uuid.UUID `gorm:"primaryKey;->;<-:create;type:uuid;"`
	CreatedAt      time.Time `gorm:"->;<-:create;"`
	CommonName     string
	CAType         string
	KeyType        string
	CertificatePEM string
	PrivateKeyPEM  string
}

// BeforeCreate - GORM hook to automatically set values
func (c *Certificate) BeforeCreate(tx *gorm.DB) (err error) {
	c.ID, err = uuid.NewV4()
	if err != nil {
		return err
	}
	c.CreatedAt = time.Now()
	return nil
}

// WGKeys - WGKeys database model
type WGKeys struct {
	// gorm.Model
	ID        uuid.UUID `gorm:"primaryKey;->;<-:create;type:uuid;"`
	CreatedAt time.Time `gorm:"->;<-:create;"`
	PrivKey   string
	PubKey    string
}

// BeforeCreate - GORM hook to automatically set values
func (c *WGKeys) BeforeCreate(tx *gorm.DB) (err error) {
	c.ID, err = uuid.NewV4()
	if err != nil {
		return err
	}
	c.CreatedAt = time.Now()
	return nil
}

type WGPeers struct {
	// gorm.Model
	ID        uuid.UUID `gorm:"primaryKey;->;<-:create;type:uuid;"`
	CreatedAt time.Time `gorm:"->;<-:create;"`
	PrivKey   string
	PubKey    string
	TunIP     string
}

// BeforeCreate - GORM hook to automatically set values
func (c *WGPeers) BeforeCreate(tx *gorm.DB) (err error) {
	c.ID, err = uuid.NewV4()
	if err != nil {
		return err
	}
	c.CreatedAt = time.Now()
	return nil
}
