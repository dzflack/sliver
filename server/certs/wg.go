package certs

import (
	"encoding/hex"
	"errors"
	"net"

	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
	"github.com/bishopfox/sliver/server/log"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gorm.io/gorm"
)

var (
	wgKeysLog = log.NamedLogger("certs", "wg-keys")

	ErrWGPeerDoesNotExist     = errors.New("WG peer does not exist")
	ErrWGServerKeysDoNotExist = errors.New("WG server keys do not exist")
)

// GetWGSPeers - Get the WG peers
func GetWGPeers() (map[string]net.IP, error) {

	peers := make(map[string]net.IP)
	wgKeysLog.Infof("Getting WG peers")

	wgPeerModel := models.WGPeer{}
	dbSession := db.Session()
	result := dbSession.Find(&wgPeerModel)
	if errors.Is(result.Error, db.ErrRecordNotFound) {
		return nil, ErrWGPeerDoesNotExist
	}
	if result.Error != nil {
		return nil, result.Error
	}
	rows, err := result.Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var wgPeer models.WGPeer
		dbSession.ScanRows(rows, &wgPeer)
		peers[wgPeer.PubKey] = wgPeer.TunIP
	}
	return peers, nil
}

// GetWGServerKeys - Get the WG server keys
func GetWGServerKeys() (string, string, error) {

	wgKeysLog.Infof("Getting WG keys for tun server")

	wgKeysModel := models.WGKeys{}
	dbSession := db.Session()
	result := dbSession.First(&wgKeysModel)
	if errors.Is(result.Error, db.ErrRecordNotFound) {
		return "", "", ErrWGServerKeysDoNotExist
	}
	if result.Error != nil {
		return "", "", result.Error
	}

	return wgKeysModel.PrivKey, wgKeysModel.PubKey, nil
}

func GenerateWGKeys(isPeer bool) (string, string, error) {
	privKey, pubKey := genWGKeys()

	if err := saveWGKeys(isPeer, privKey, pubKey); err != nil {
		wgKeysLog.Error("Error Saving WG keys: ", err)
		return "", "", err
	}
	return privKey, pubKey, nil
}

func genWGKeys() (string, string) {
	wgKeysLog.Infof("Generating WG keys")

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		wgKeysLog.Fatalf("Failed to generate private key: %s", err)
	}
	publicKey := privateKey.PublicKey()
	return hex.EncodeToString(privateKey[:]), hex.EncodeToString(publicKey[:])
}

// saveWGKeys - Save WG keys to the filesystem
func saveWGKeys(isPeer bool, privKey string, pubKey string) error {

	wgKeysLog.Infof("Saving WG keys")
	dbSession := db.Session()

	var result *gorm.DB

	if isPeer {
		wgPeerModel := &models.WGPeer{
			PrivKey: privKey,
			PubKey:  pubKey,
		}
		result = dbSession.Create(&wgPeerModel)

	} else {
		wgKeysModel := &models.WGKeys{
			PrivKey: privKey,
			PubKey:  pubKey,
		}
		result = dbSession.Create(&wgKeysModel)
	}

	return result.Error
}
