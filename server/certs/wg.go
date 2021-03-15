package certs

import (
	"encoding/hex"
	"errors"

	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
	"github.com/bishopfox/sliver/server/log"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	wgKeysLog = log.NamedLogger("certs", "wg-keys")

	ErrWGPeerDoesNotExist     = errors.New("WG peer does not exist")
	ErrWGServerKeysDoNotExist = errors.New("WG server keys do not exist")
)

// GetWGSPeers - Get the WG peers
func GetWGPeers() (map[string]string, error) {

	peers := make(map[string]string)
	wgKeysLog.Infof("Getting WG peers")

	wgPeersModel := models.WGPeers{}
	dbSession := db.Session()
	result := dbSession.Find(&wgPeersModel)
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
		var wgPeer models.WGPeers
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

func GenerateWGServerKeys() (string, string, error) {
	privKey, pubKey := genWGServerKeys()

	if err := saveWGServerKeys(privKey, pubKey); err != nil {
		return "", "", err
	}
	return privKey, pubKey, nil
}

func genWGServerKeys() (string, string) {
	wgKeysLog.Infof("Generating WG keys for tun server")

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		wgKeysLog.Fatalf("Failed to generate private key: %s", err)
	}
	publicKey := privateKey.PublicKey()
	return hex.EncodeToString(privateKey[:]), hex.EncodeToString(publicKey[:])
}

// saveWGServerKeys - Save WG server keys to the filesystem
func saveWGServerKeys(privKey string, pubKey string) error {

	wgKeysLog.Infof("Saving WG keys for tun server")

	certModel := &models.WGKeys{
		PrivKey: privKey,
		PubKey:  pubKey,
	}

	dbSession := db.Session()
	result := dbSession.Create(&certModel)

	return result.Error
}
