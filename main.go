//go:build windows

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	ZephyrMinerPath string = "C:\\Windows\\System32\\winsvcf"
	err             error
)

func isInfected() bool {
	if _, err := os.Stat(ZephyrMinerPath); os.IsNotExist(err) {
		return false
	}

	return true
}

func isAdmin() bool {
	var sid *windows.SID
	err = windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2, windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false
	}
	token, _ := windows.Token(0).IsMember(sid)
	return token
}

func disableZephyrService() error {
	svcPatternName := `^x\d{6}`
	re := regexp.MustCompile(svcPatternName)

	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()

	services, err := manager.ListServices()
	if err != nil {
		return err
	}

	for _, svcName := range services {
		if re.MatchString(svcName) {
			log.Println("Service Found: " + svcName)
			service, err := manager.OpenService(svcName)
			if err != nil {
				return err
			}
			defer service.Close()

			status, err := service.Query()
			if err != nil {
				return err
			}

			config, err := service.Config()
			if err != nil {
				return err
			}

			//Disable the service
			config.StartType = mgr.StartDisabled
			if err = service.UpdateConfig(config); err != nil {
				return err
			}

			//Stop the service
			if _, err = service.Control(svc.Stop); err != nil {
				log.Println("[-] " + err.Error())
			}
			for i := 0; i < 10; i++ {
				status, err = service.Query()
				if err != nil {
					return err
				}
				if status.State == svc.Stopped {
					// Delete the service
					if err = service.Delete(); err != nil {
						return err
					}
					time.Sleep(3 * time.Second)
					// Remove the malware used by the service
					if err = os.Remove(filepath.Join("C:\\Windows\\System32", svcName+".dat")); err != nil {
						return err
					}
					break
				}
				time.Sleep(1 * time.Second)
			}

		}

	}

	return nil
}

func removeZephyrFiles(folderPath string) error {
	if isInfected() {
		if err = os.RemoveAll(folderPath); err != nil {
			return err
		}
	}

	return nil
}

func removeDefenderExclusions() error {
	exclusions := exec.Command("powershell", "-Command", "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath")
	output, err := exclusions.Output()
	if err != nil {
		return err
	}

	excludedPaths := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(excludedPaths) == 0 || excludedPaths[0] == "" {
		return errors.New("No exclusions found in defender")
	}

	for _, path := range excludedPaths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}

		removeExcludedPath := exec.Command("powershell", "-Command", "Remove-MpPreference -ExclusionPath \""+path+"\"")
		if err = removeExcludedPath.Run(); err != nil {
			return err
		}
	}

	return nil
}

func main() {

	fmt.Println(`
  ____         _            __  __ _                ___                           
 |_  /___ _ __| |_ _  _ _ _|  \/  (_)_ _  ___ _ _  | _ \___ _ __  _____ _____ _ _ 
  / // -_) '_ \ ' \ || | '_| |\/| | | ' \/ -_) '_| |   / -_) '  \/ _ \ V / -_) '_|
 /___\___| .__/_||_\_, |_| |_|  |_|_|_||_\___|_|   |_|_\___|_|_|_\___/\_/\___|_|  
         |_|       |__/                                                           
		 ZephyerMiner Malware Remover - r0ttenbeef
	`)

	if !isAdmin() {
		log.Println("[x] This program must be run as an administrator!")
		os.Exit(1)
	}

	if isInfected() {
		log.Println("[*] Your device might be infected with ZephyrMiner malware")
	} else {
		log.Println("[+] Your device might not infected with ZephyrMiner .. Will keep checking")
	}

	log.Println("[*] Disable and remove the running service")
	if err = disableZephyrService(); err != nil {
		log.Println("[-] " + err.Error())
	}

	log.Println("[*] Removing zephyr mining files")
	if err = removeZephyrFiles(ZephyrMinerPath); err != nil {
		log.Println("[-] " + err.Error())
	}

	log.Println("[*] Removing exclusions from windows defender")
	if err = removeDefenderExclusions(); err != nil {
		log.Println("[-] " + err.Error())
	}

}
