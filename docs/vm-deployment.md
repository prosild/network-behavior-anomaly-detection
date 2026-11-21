# 배포 VM 만들기와 실습망 연결(DD-015)

- 결정: [DD-015](design-decisions/DD-015-vmware-lab-deployment.md). 구성 파일: [deploy/compose.yaml](../deploy/compose.yaml)
- 이 문서는 아무것도 없는 상태에서 시작해 한 단계씩 따라 하도록 썼다. 끝까지 하면 이 PC의 VMware에 배포 VM(Ubuntu Server)과 Kali VM이 생기고, Kali의 트래픽이 수집 → Zeek → 채점 → 에이전트로 이어진다.
- 이 PC에서 같은 순서를 미리 해 봤다(별도 Compose 프로젝트, 2026-11-18). 코드 묶음만으로 이미지가 빌드되고, 가져온 DB로 다시 계산한 점수가 원래와 같았다([단계 6 진행 기록](stage-6-progress.md) 열한째·열두째 작업).
- 각 단계 끝의 **확인**이 기대와 다르면 다음 단계로 넘어가지 말고, 단계 번호와 화면 내용을 Claude에게 보낸다.

## 전체 모습

```
                 Windows (이 PC)
                   │  브라우저 → http://<배포 VM NAT 주소>:5000 (MLflow 화면)
                   │  WSL → ssh zeekad-vm (관리)
   VMnet8 (NAT) ───┤  인터넷: Gemini API, 패키지
                   │
   ┌───────────────┴──────────────┐
   │ 배포 VM (Ubuntu Server 24.04) │  카드 1: NAT (관리·인터넷, DHCP)
   │  Docker Compose               │  카드 2: VMnet2 10.10.0.10 (실습망, 기본 경로 없음)
   │  collector(tcpdump: 카드 2만) │
   │  pipeline · api · mlflow · DB │
   └───────────────┬──────────────┘
   VMnet2 (host-only, Windows 연결 없음, DHCP 없음, 10.10.0.0/24)
                   │
            Kali VM 10.10.0.50  (카드는 VMnet2 하나뿐)
```

- **VMnet8(NAT)**: VMware가 기본으로 만드는 가상 네트워크다. 이 네트워크에 붙은 VM은 Windows를 거쳐 인터넷에 나가고, Windows와 WSL에서 VM에 접속할 수 있다. 주소는 VMware의 DHCP가 자동으로 준다.
- **VMnet2(host-only)**: 이번에 새로 만드는 실습망이다. 인터넷도 Windows도 연결하지 않는다. 그래서 Kali가 닿는 곳은 배포 VM 하나뿐이다. DHCP도 없으므로 주소는 직접 정한다.
- 실습망 대역은 시험 PCAP과 같은 `10.10.0.0/24`로 둔다. 그래서 [configs/assets.lab.v1.json](../configs/assets.lab.v1.json)을 고치지 않는다. 시험 데이터(`lab-20261201`)와는 날짜(캡처 ID)가 달라 섞이지 않는다.

## 권장 사양(실측 근거)

| VM | CPU | 메모리 | 디스크 | 근거 |
| --- | --- | --- | --- | --- |
| 배포 VM | 4 (processors 1 × cores 4) | 8GB | 60GB | 다시 계산(파일 8개, CPU 4개 제한): 167초, 최고 메모리 1.97GB. DB·MLflow·API와 이후 Java 대시보드를 더해도 8GB 안. 이미지 약 6GB, 리비전 하나 86MB |
| Kali VM | 2 | 4GB | 공식 VMware 이미지 기본값 | |

- CPU 수는 VM 안에서 보이는 CPU의 합계다. VMware의 `Number of processors`와 `Number of cores per processor`를 곱한 값이다. 데스크톱 CPU는 소켓이 하나이므로 1 × 4로 둔다. VM의 CPU 하나는 호스트의 논리 프로세서(스레드) 하나에 대응한다(Ryzen 5700X는 16개).
- 다시 계산 시간은 CPU 12개일 때와 같았다(대부분 단계마다 Spark를 띄우는 시간).
- 이 PC의 메모리는 WSL, VM 두 대, Windows가 나눠 쓴다. VM을 켤 때 WSL에서 큰 실험이 돌고 있으면 메모리가 모자랄 수 있다.

## 0. 예전에 만든 VM 지우기(처음 하는 경우 건너뛴다)
이 문서의 이전 판으로 만들던 배포 VM이 있으면 지우고 새로 만든다.
1. VMware 왼쪽 `Library`에서 그 VM을 고른다. 켜져 있으면 `VM → Power → Shut Down Guest`로 끈다.
2. `VM → Manage → Delete from Disk` → `Yes`.

VMnet2를 이미 만들었다면 지우지 않아도 된다. 2단계에서 설정이 맞는지만 확인한다.

## 1. 준비물 받기(Windows)
1. **VMware Workstation Pro**: Broadcom 지원 포털(https://support.broadcom.com)에 무료 계정으로 로그인한 뒤 `My Downloads`에서 `VMware Workstation Pro`의 Windows 판을 받아 설치한다. 개인 사용은 무료다.
2. **Ubuntu Server 24.04 LTS ISO**: https://ubuntu.com/download/server 에서 `Ubuntu Server 24.04.x LTS`를 받는다(약 3GB, 파일 이름 `ubuntu-24.04.x-live-server-amd64.iso`). Desktop 판이 아니라 Server 판이다.
3. **Kali Linux VMware 이미지**: https://www.kali.org/get-kali/ → `Virtual Machines` → `VMware` 64-bit를 받는다(`.7z` 파일, 약 3GB). 11단계에서 쓴다.

## 2. 실습망 가상 네트워크 VMnet2 만들기(VMware)
1. VMware를 연다. 메뉴 `Edit → Virtual Network Editor…`를 연다.
2. 오른쪽 아래 `Change Settings`를 누른다. 관리자 권한 창(UAC)이 뜨면 `예`를 누른다. 이 단계를 거쳐야 설정을 바꿀 수 있다.
3. `Add Network…`를 누르고 `Select a network to add`에서 `VMnet2`를 고른 뒤 `OK`를 누른다.
4. 목록에서 `VMnet2` 줄을 고르고 아래 `VMnet Information`을 다음처럼 맞춘다.

   | 항목 | 값 | 이유 |
   | --- | --- | --- |
   | `Bridged` / `NAT` / `Host-only` | **`Host-only`** | 바깥(인터넷·집 LAN)과 연결하지 않는다 |
   | `Connect a host virtual adapter to this network` | **해제** | Windows가 이 네트워크에 들어가지 않는다. Kali가 Windows에 닿지 못한다 |
   | `Use local DHCP service to distribute IP address to VMs` | **해제** | 주소를 직접 정한다(배포 VM 10.10.0.10, Kali 10.10.0.50) |
   | `Subnet IP` | `10.10.0.0` | |
   | `Subnet mask` | `255.255.255.0` | |

5. 목록에서 `VMnet8` 줄을 고르고 확인만 한다. `NAT`이고 `Use local DHCP service…`가 **체크되어 있어야** 한다. `Subnet IP`(예: `192.168.150.0`)를 적어 둔다. 배포 VM의 관리 주소가 이 대역에서 나온다.
6. `Apply` → `OK`.

**확인**
- Windows PowerShell에서 `ipconfig`를 실행한다. `VMware Network Adapter VMnet8`은 있고 `VMware Network Adapter VMnet2`는 **없어야** 한다.
- 집 LAN 주소가 `10.10.0.x`가 아닌지도 본다(대부분 `192.168.x.x`). 겹치면 Claude에게 알린다.

## 3. 배포 VM 만들기(VMware)
이 단계에서는 **NAT 카드 하나만** 단다. 실습망 카드(VMnet2)는 Ubuntu 설치가 끝난 뒤 6단계에서 단다. 설치 프로그램이 실습망 카드를 DHCP로 설정해 부팅이 멈추는 일을 막기 위해서다.

1. `File → New Virtual Machine…`
2. `Typical (recommended)` → `Next`.
3. `Guest Operating System Installation`: **`I will install the operating system later`** → `Next`.
   - ISO를 여기서 고르면 VMware가 자동 설치(Easy Install)를 할 수 있다. 그러면 아래 설치 화면의 선택을 직접 할 수 없으므로 나중에 붙인다.
4. `Select a Guest Operating System`: `Linux`, Version `Ubuntu 64-bit` → `Next`.
5. `Name the Virtual Machine`: 이름 `zeekad-deploy`. 위치는 여유 공간이 60GB 넘는 드라이브로 한다 → `Next`.
6. `Specify Disk Capacity`: `Maximum disk size` **60** GB, `Store virtual disk as a single file` → `Next`.
   - 디스크는 실제로 쓴 만큼만 Windows 공간을 차지한다.
7. `Ready to Create Virtual Machine`에서 **`Customize Hardware…`**를 누른다.

   | 왼쪽 항목 | 설정 |
   | --- | --- |
   | `Memory` | `8192` MB |
   | `Processors` | `Number of processors` **1**, `Number of cores per processor` **4**. 아래 `Virtualization engine`의 체크 칸은 모두 해제한 채로 둔다(WSL과 함께 쓸 때 켜면 VM이 켜지지 않을 수 있다) |
   | `New CD/DVD (SATA)` | `Use ISO image file` → `Browse…`로 Ubuntu Server ISO를 고른다. `Connect at power on` 체크 |
   | `Network Adapter` | **`NAT: Used to share the host's IP address`**. `Connect at power on` 체크 |
   | `USB Controller`, `Sound Card`, `Printer` | 고르고 `Remove`(필요 없다. 없으면 넘어간다) |

   `Close` → `Finish`.

**확인**: `Library`에 `zeekad-deploy`가 생기고, 오른쪽 요약에 Memory 8 GB, Processors 4, Hard Disk 60 GB, Network Adapter NAT가 보인다. Network Adapter는 하나뿐이다.

## 4. Ubuntu Server 설치(배포 VM 콘솔)
`zeekad-deploy`를 고르고 `Power on this virtual machine`을 누른다.

- 콘솔 화면을 한 번 클릭하면 키보드가 VM으로 들어간다. 마우스·키보드를 Windows로 되돌릴 때는 `Ctrl+Alt`를 누른다.
- 설치 화면은 방향키로 움직이고 `Enter`로 고르며, `Space`로 체크 칸을 켜고 끈다. 화면 아래 `[ Done ]`으로 다음 화면에 간다.
- 콘솔에는 붙여 넣기가 되지 않는다. 설치가 끝나면 5단계부터는 WSL에서 SSH로 접속해 명령을 붙여 넣는다.

화면 순서대로 다음처럼 고른다.

1. **GRUB 메뉴**: `Try or Install Ubuntu Server` → `Enter`.
2. **`Welcome!`(언어)**: `English`. 서버 콘솔은 한글을 표시하지 못하고, 오류 메시지를 검색하기도 영어가 쉽다.
3. **`Installer update available`**(나오는 경우): `Continue without updating`.
4. **`Keyboard configuration`**: Layout `English (US)`, Variant `English (US)` → `Done`. 한국어 키보드도 영문 배열이 같아서 이대로 쓴다.
5. **`Choose the type of installation`**: `(X) Ubuntu Server`(minimized 아님). `Search for third-party drivers`는 해제 → `Done`.
6. **`Network configuration`**: 카드가 하나(예: `ens33`, 종류 `eth`) 보인다.
   - 바라는 상태: 카드 아래에 `DHCPv4  192.168.x.x/24`가 표시된다(x는 2단계에서 적은 VMnet8 대역).
   - 주소가 없거나 `disabled`이면: 카드를 고르고 `Enter` → `Edit IPv4` → `IPv4 Method`를 `Automatic (DHCP)` → `Save`. 잠시 뒤 주소가 나타난다.
   - IPv6는 `Disabled`로 둔다. VMware NAT은 기본으로 IPv6를 주지 않는다. DHCP로 두면 부팅 때 오지 않을 주소를 기다리느라 1\~2분씩 멈출 수 있다. `Edit IPv6`에서 `Disabled`인지 확인한다.
   - **이 `192.168.x.x` 주소를 적어 둔다.** 앞으로 `<NAT 주소>`라고 부른다. 관리 접속과 MLflow 화면 주소다.
   - 확인되면 `Done`.
   - 주소가 끝내 안 잡히면 Windows `services.msc`에서 `VMware DHCP Service`와 `VMware NAT Service`가 실행 중인지 본다.
7. **`Proxy configuration`**: 비워 둔다 → `Done`.
8. **`Ubuntu archive mirror configuration`**: 기본값 그대로. `This mirror location passed tests`가 나오면 → `Done`. 실패가 나오면 6번의 인터넷 연결 문제다.
9. **`Guided storage configuration`**:
   - `(X) Use an entire disk`(60GB 디스크 하나가 골라져 있다).
   - **`Set up this disk as an LVM group`은 해제한다.** 켜 두면 설치 프로그램이 디스크의 절반(약 30GB)만 `/`에 주고 나머지를 비워 둔다. Docker 이미지·리비전이 그 절반 안에 쌓이게 된다.
   - `Done`.
10. **`Storage configuration`**(요약): `USED DEVICES`에 `/`가 `ext4`, 약 58GB로 보이면 맞다 → `Done` → `Confirm destructive action`에서 `Continue`. 새 가상 디스크만 지우므로 Windows 파일과는 상관없다.
11. **`Profile configuration`**:
    - `Your name`: 아무 이름
    - `Your servers name`: `zeekad-deploy`
    - `Pick a username`: 소문자 계정 이름(예: `ops`). 앞으로 `<사용자>`라고 부른다.
    - 비밀번호 두 번 → `Done`.
    - 이 첫 계정의 uid는 자동으로 1000이 된다. 컨테이너 계정(uid 1000)과 같아서 수집 파일과 결과 파일의 주인이 맞는다.
12. **`Upgrade to Ubuntu Pro`**: `Skip for now` → `Continue`.
13. **`SSH configuration`**:
    - **`[X] Install OpenSSH server`를 켠다.**
    - `Import SSH key`는 `No`.
    - `Allow password authentication over SSH`가 보이면 켠 채로 둔다. 5단계에서 키를 넣은 뒤 끈다.
    - `Done`.
14. **`Featured server snaps`**: **아무것도 고르지 않는다**(특히 `docker`는 고르지 않는다. snap 판 Docker는 7단계에서 설치할 공식 Docker와 충돌한다) → `Done`.
15. 설치가 진행된다. `Installation complete!`가 나오면 `Reboot Now`.
    - `Please remove the installation medium, then press ENTER`가 나오면 그냥 `Enter`. VMware가 ISO를 알아서 뗀다.
    - 다시 설치 화면이 뜨면 `VM → Settings → CD/DVD`에서 `Connected`를 해제하고 `VM → Power → Restart Guest`.
16. 부팅이 끝나면 `zeekad-deploy login:`이 나온다. 11번의 계정으로 로그인한다. 중간에 `cloud-init` 메시지가 몇 줄 섞여 나와도 정상이다. 로그인 프롬프트가 안 보이면 `Enter`를 한 번 누른다.

**확인**(콘솔에서)
```bash
id -u            # 1000
ip -br addr      # lo, ens33 UP 192.168.x.x/24 두 줄
df -h /          # Size 약 58G
ping -c 2 ubuntu.com
```

## 5. WSL에서 SSH로 접속하기(키 로그인)
이제부터는 콘솔 대신 WSL 터미널에서 접속해 명령을 붙여 넣는다. 접속은 비밀번호 대신 **SSH 키**로 한다. 키는 WSL에만 있는 개인 키와 VM에 넣는 공개 키 한 쌍이다. 공개 키가 들어 있는 계정에는 개인 키를 가진 쪽만 들어갈 수 있다. 비밀번호 로그인을 끄면 실습망의 Kali가 비밀번호를 대입해도 들어올 수 없다.

**WSL에서**
```bash
ssh-keygen -t ed25519 -f ~/.ssh/zeekad_vm -C zeekad-vm     # 암호 문구는 비워도 된다(Enter 두 번)
```
`~/.ssh/config`에 다음을 더한다(`<NAT 주소>`, `<사용자>`는 4단계 값).
```
Host zeekad-vm
    HostName <NAT 주소>
    User <사용자>
    IdentityFile ~/.ssh/zeekad_vm
```
```bash
chmod 600 ~/.ssh/config
ssh-copy-id -i ~/.ssh/zeekad_vm.pub zeekad-vm   # 처음에는 "Are you sure…" → yes, 그다음 VM 비밀번호
ssh zeekad-vm                                   # 비밀번호를 묻지 않고 들어가면 성공
```
- WSL에서 `<NAT 주소>`로 접속이 안 되면(시간 초과) Windows PowerShell에서 `ssh <사용자>@<NAT 주소>`가 되는지 보고 Claude에게 알린다.

**배포 VM에서**(`ssh zeekad-vm`으로 들어간 상태): 비밀번호 로그인을 끈다.
```bash
sudo tee /etc/ssh/sshd_config.d/01-zeekad.conf > /dev/null <<'EOF'
# 키 로그인만 허용한다(실습망에서 비밀번호 대입 공격이 들어와도 실패하게)
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
sudo sshd -t && sudo systemctl restart ssh
sudo sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication) '
```
- 파일 이름을 `01-`로 시작하는 이유: 설치 프로그램이 `50-cloud-init.conf`에 `PasswordAuthentication yes`를 넣어 두는 경우가 있다. sshd는 같은 항목을 여러 번 만나면 **먼저 읽은 값**을 쓰고, 파일은 이름 순서로 읽는다.

**확인**
- 마지막 명령 결과가 `passwordauthentication no`, `kbdinteractiveauthentication no` 두 줄이다.
- **지금 접속은 끊지 말고** WSL에서 새 터미널을 열어 `ssh zeekad-vm`이 되는지 본다. 안 되면 열려 있는 접속에서 `sudo rm /etc/ssh/sshd_config.d/01-zeekad.conf && sudo systemctl restart ssh`로 되돌린다. 콘솔 로그인(비밀번호)은 이 설정과 상관없이 계속 된다.

**배포 VM에서**: 패키지를 최신으로 올리고 시간을 확인한다.
```bash
sudo apt-get update && sudo apt-get -y full-upgrade
sudo apt-get install -y open-vm-tools       # 보통 이미 설치되어 있다. VMware가 VM을 정상 종료·재시작할 때 쓴다
timedatectl                                 # Time zone: Etc/UTC, System clock synchronized: yes
sudo reboot
```
- 시간대는 UTC 그대로 둔다. 수집 파일 이름과 날짜(캡처 ID `lab-YYYYMMDD`)는 UTC 기준이다.
- 시계 동기화가 `no`이면 1\~2분 뒤 다시 본다. 패킷 시각이 틀리면 창 점수가 엉뚱한 날짜에 쌓인다.

## 6. 실습망 카드(VMnet2) 달고 주소 정하기
1. VM을 끈다: `ssh zeekad-vm` → `sudo poweroff`. VMware 화면에서 `Powered Off`가 될 때까지 기다린다.
2. VMware에서 `zeekad-deploy`를 고르고 `VM → Settings…` → 아래 `Add…` → `Network Adapter` → `Finish`.
3. 새로 생긴 `Network Adapter 2`를 고른다.
   - `Device status`: `Connect at power on` 체크. `Connected`는 VM이 꺼져 있을 때 회색(선택 불가)이다. 정상이다. 켜지면 `Connect at power on`에 따라 연결된다.
   - `Network connection`: **`Custom: Specific virtual network` → `VMnet2`**. 목록에는 `(Host-only)` 같은 설명 없이 `VMnet2`로만 보일 수 있다. Host-only인지는 VMnet2라는 이름이 아니라 2단계 `Virtual Network Editor` 설정이 정한다.
   - `OK`.
   - 걱정되면 `Edit → Virtual Network Editor…`를 다시 열어 표에서 VMnet2 줄이 `Type: Host-only`, `External Connection: -`, `Host Connection: -`, `DHCP: -`, `Subnet Address: 10.10.0.0`인지 본다. VMnet2 줄이 없으면 2단계에서 `Apply`가 되지 않은 것이므로 2단계를 다시 한다.
4. VM을 켜고(`Power on this virtual machine`) WSL에서 `ssh zeekad-vm`.
5. 새 카드 이름을 확인한다.
   ```bash
   ip -br addr
   # lo     UNKNOWN 127.0.0.1/8 ...
   # ens33  UP      192.168.x.x/24 ...      ← NAT 카드(관리)
   # ens37  DOWN                            ← 새 카드(실습망). 이름은 다를 수 있다
   ```
   주소가 없는 새 카드의 이름이 앞으로의 `<실습망 카드>`다. 아래에서 `LAB=` 뒤에 넣는다.
6. 실습망 카드 설정 파일을 만든다. 첫 줄의 `ens37`만 5번에서 본 이름으로 바꿔 통째로 붙여 넣는다.
   ```bash
   LAB=ens37
   sudo tee /etc/netplan/60-lab.yaml > /dev/null <<EOF
   # 실습망(VMnet2) 카드: 고정 주소만 둔다.
   # 기본 경로(routes)를 두지 않는다. 인터넷 트래픽은 NAT 카드로만 나간다.
   # IPv6(자동 주소·link-local)를 끈다. 캡처에 실습과 상관없는 IPv6 잡음이 섞이지 않게.
   network:
     version: 2
     ethernets:
       $LAB:
         dhcp4: false
         dhcp6: false
         accept-ra: false
         link-local: []
         addresses: [10.10.0.10/24]
   EOF
   sudo chmod 600 /etc/netplan/60-lab.yaml
   sudo netplan apply
   ```
   - `chmod 600`: netplan은 다른 사용자가 읽을 수 있는 설정 파일에 경고를 낸다.
   - `netplan apply` 때 SSH가 잠깐 멈출 수 있지만 끊기지는 않는다(NAT 카드 설정은 그대로).

**확인**
```bash
ip -br addr                  # ens37 UP 10.10.0.10/24
ip route                     # default via 192.168.x.2 dev ens33 ... 한 줄만 default로 시작한다
                             # 10.10.0.0/24 dev ens37 ... 한 줄
sudo grep -rl ens37 /etc/netplan/   # ens37은 실습망 카드 이름으로 바꾼다. /etc/netplan/60-lab.yaml 하나만
                                    # (netplan 파일은 root만 읽을 수 있어 sudo가 필요하다)
```
`default`로 시작하는 줄이 ens37에도 있으면 Claude에게 알린다.

## 7. Docker 설치(배포 VM)
Docker 공식 저장소에서 설치한다(https://docs.docker.com/engine/install/ubuntu/). 아래를 통째로 붙여 넣는다.
```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
exit
```
- `usermod -aG docker`: `sudo` 없이 `docker` 명령을 쓰게 한다. 그룹은 다시 로그인해야 적용되므로 마지막에 `exit`로 나간다.
- docker 그룹은 root와 같은 권한이다. 이 VM 전용 계정이라 허용한다.

**확인**: WSL에서 다시 `ssh zeekad-vm` 한 뒤
```bash
docker run --rm hello-world      # "Hello from Docker!"
docker compose version           # Docker Compose version v2.x
```

**스냅숏(권장)**: VMware에서 `VM → Snapshot → Take Snapshot…`, 이름 `docker-ready`. 뒤 단계가 꼬이면 `VM → Snapshot → Revert to Snapshot`으로 여기로 돌아온다.

## 8. 묶음 만들어 옮기기
**이 PC(WSL, 프로젝트 루트 `~/src/zeek_AD`)**: 묶음을 만들고 `.env`와 함께 보낸다. 묶음 만들기는 Claude에게 맡겨도 된다.
```bash
rm -rf ~/zeekad-bundle                              # 예전 묶음이 있으면(스크립트는 이미 있는 폴더에 쓰지 않는다)
deploy/export_bundle.sh ~/zeekad-bundle             # DB 덤프 + 필요한 파일 46MB + 코드(code.tar) + 해시. 1분 안쪽
scp -r ~/zeekad-bundle zeekad-vm:~/
scp deploy/.env zeekad-vm:~/zeekad.env
```
- 묶음에는 비밀값이 없다. `.env`(DB 비밀번호·Gemini 키)는 따로 보낸다. 값을 화면에 출력하지 않는다.

**배포 VM**(`ssh zeekad-vm`):
```bash
mkdir ~/zeek_AD && tar -xf ~/zeekad-bundle/code.tar -C ~/zeek_AD
install -m 600 ~/zeekad.env ~/zeek_AD/deploy/.env && rm ~/zeekad.env
cd ~/zeek_AD
ls                     # configs  db  deploy  scripts  tests  zeek_ad
```
`deploy/.env` 끝에 이 VM의 값을 더한다. `<NAT 주소>`와 `<실습망 카드>`를 4·6단계 값으로 바꿔 붙여 넣는다.
```bash
cat >> deploy/.env <<'EOF'
# 배포 VM 값(DD-015)
MGMT_BIND=<NAT 주소>
LAB_IFACE=<실습망 카드>
ROTATE_SECONDS=300
EOF
```
- `MGMT_BIND`: MLflow 화면을 이 주소에만 연다. 실습망 주소(10.10.0.10)를 넣으면 Kali에서 화면이 보이므로 넣지 않는다.
- `LAB_IFACE`: tcpdump가 이 카드만 캡처한다. NAT 카드 이름을 넣으면 관리·인터넷 트래픽이 캡처된다.
- VMware NAT의 DHCP는 같은 VM에 보통 같은 주소를 다시 준다. 혹시 `ens33` 주소가 바뀌면 `MGMT_BIND`도 고치고 `mlflow` 서비스를 다시 띄운다.

**확인**
```bash
grep -E '^(MGMT_BIND|LAB_IFACE|ROTATE_SECONDS)=' deploy/.env    # 세 줄, 값이 4·6단계와 같다
stat -c '%a %U' deploy/.env                                       # 600 <사용자>
```

## 9. 빌드, 가져오기, 띄우기(배포 VM, `~/zeek_AD`)
`DC`는 긴 명령을 줄여 쓰는 셸 변수다. **SSH로 새로 접속할 때마다 첫 줄을 다시 실행한다.**
```bash
cd ~/zeek_AD
DC="docker compose -f deploy/compose.yaml --env-file deploy/.env"
$DC --profile app build                       # 처음에는 10~20분. Zeek·torch 등 수 GB를 받는다
deploy/import_bundle.sh ~/zeekad-bundle       # Postgres만 띄우고 DB 복원, MLflow 경로를 /app으로, 파일 풀기
$DC --profile app up -d
$DC --profile app ps                          # postgres·api·mlflow (healthy), pipeline·collector Up
$DC logs collector                            # "캡처 시작: <실습망 카드>, 300초 경계마다 파일 회전(패킷이 없어도)"
$DC logs pipeline                             # "감시 시작: data/live/inbox"
```
- 가져오기 출력의 `5.`에서 `이 PC 경로가 남은 값 0개`가 zeekad·mlflow 두 줄 모두 나와야 한다.
- `healthy`가 되기까지 30초쯤 걸린다. `starting`이면 잠시 뒤 다시 `ps`를 본다.
- VM을 껐다 켜면 서비스가 다시 올라온다(`restart: unless-stopped`). 수집기는 멈출 때 쓰던 파일을 마무리해 넘긴다. 갑자기 꺼져 남은 파일은 다시 시작할 때 넘긴다.
- 수집기는 시계의 5분 경계(:00, :05, …)마다 파일을 넘긴다. 트래픽이 있던 5분만 파일이 생기고(`lab-<시작>-<끝>.pcap`), 조용한 5분의 빈 파일은 버린다(DD-016).

**스냅숏(권장)**: `VM → Snapshot → Take Snapshot…`, 이름 `pipeline-up`.

## 10. 노출과 격리 확인
**배포 VM**:
```bash
sudo ss -ltnp | grep -E ':(5432|55432|8000|5000|22) '
```

| 보여야 하는 줄 | 뜻 |
| --- | --- |
| `127.0.0.1:55432` | DB. VM 안에서만 열린다 |
| `127.0.0.1:8000` | 근거 API. VM 안에서만 열린다 |
| `<NAT 주소>:5000` | MLflow 화면. 관리용 주소에만 열린다 |
| `0.0.0.0:22`, `[::]:22` | SSH. 모든 카드에 열린다. 실습망에서 보이는 서비스는 이것 하나이고, 키 로그인만 받는다(5단계) |

`0.0.0.0:5000`, `0.0.0.0:8000`, `0.0.0.0:55432`, `10.10.0.10:…`이 보이면 멈추고 Claude에게 알린다.

**Windows 브라우저**: `http://<NAT 주소>:5000/#/models`를 연다(모델 목록 화면으로 바로 간다). `zeekad-fusion`과 `Version 1`이 보이면 된다.
- MLflow 3 화면에서는 메뉴가 위쪽이 아니라 **왼쪽 세로 메뉴**에 있다(`Experiments`, `Models` 등). 왼쪽 메뉴가 접혀 있거나 `Models`가 안 보이면 위 주소로 바로 간다.

## 11. Kali VM 만들기와 연결
1. 받은 `.7z`를 푼다(Windows 11 탐색기에서 `모두 압축 풀기`, 또는 7-Zip). 여유 공간이 넉넉한 곳에 둔다.
2. VMware에서 `File → Open…` → 푼 폴더의 `.vmx` 파일을 고른다. `Library`에 Kali VM이 생긴다.
3. **켜기 전에** `VM → Settings…`:
   - `Memory`: `4096` MB, `Processors`: 합계 2.
   - `Network Adapter`: **`Custom: Specific virtual network` → `VMnet2 (Host-only)`**.
   - `Network Adapter 2` 같은 다른 카드가 있으면 고르고 `Remove`. **카드는 VMnet2 하나만** 둔다.
   - `OK`.
   - Kali 이미지에 nmap·hydra 등 시험 도구가 이미 들어 있다. 인터넷에 연결하지 않고 쓴다. 패키지를 갱신하려고 NAT 카드를 잠시 붙였다면 시험 전에 다시 떼어 낸다.
4. Kali를 켠다. `I Moved It` / `I Copied It`를 물으면 `I Copied It`.
5. 로그인: 사용자 `kali`, 비밀번호 `kali`.
   - 비밀번호는 바꾸지 않아도 된다. Kali에 접속할 수 있는 곳은 실습망의 배포 VM뿐이고, Kali 이미지는 SSH 서버가 기본으로 꺼져 있다. 바꾸고 싶으면 터미널에서 `passwd`.
6. 고정 IP를 설정한다(기본 경로 없음). 켠 직후 오른쪽 위 네트워크 표시가 `Disconnected`이고 `ip route`가 비어 있는 것은 정상이다. Kali는 처음에 DHCP로 주소를 받으려 하는데, VMnet2에는 DHCP가 없어서 실패한 상태다.
   Kali 터미널에서 카드 이름을 확인한다.
   ```bash
   ip -br link                 # lo, eth0 두 줄. eth0 상태는 UP 또는 DOWN(주소가 없어서). 이름이 다르면 아래 eth0을 바꾼다
   ```
   실습망 전용 연결 `lab`을 새로 만든다. 기존 DHCP 연결(`Wired connection 1` 등)은 지우지 않는다. `lab`의 우선순위를 높여 부팅 때마다 `lab`이 먼저 붙는다.
   ```bash
   sudo nmcli connection add type ethernet ifname eth0 con-name lab \
        ipv4.method manual ipv4.addresses 10.10.0.50/24 ipv4.never-default yes \
        ipv6.method disabled connection.autoconnect-priority 10
   sudo nmcli connection up lab
   nmcli device status         # eth0  ethernet  connected  lab
   ```
   - `ipv4.never-default yes`: 이 연결을 기본 경로로 쓰지 않는다. 인터넷으로 나갈 길이 아예 없다.
   - `nmcli connection up lab`에서 오류가 나면 `ip -br link`의 eth0 상태와 VMware의 Kali `Network Adapter`가 `Connected`·`VMnet2`인지 본다.

**확인**(Kali 터미널)
```bash
ip -br addr                 # eth0 UP 10.10.0.50/24
ip route                    # 10.10.0.0/24 dev eth0 ... 한 줄뿐(default 없음)
ping -c 2 10.10.0.10        # 배포 VM: 응답 온다
ping -c 2 8.8.8.8           # 인터넷: "Network is unreachable"
ping -c 2 <Windows의 집 LAN 주소>   # "Network is unreachable"
curl -m 5 http://10.10.0.10:5000    # MLflow 화면: 연결 실패(Connection refused)
```
배포 VM에서도 `ping -c 2 10.10.0.50`이 되는지 본다.

## 12. 첫 동작 확인
Kali에서 가벼운 트래픽을 만든다.
```bash
ping -c 20 10.10.0.10
nmap -sT -p 1-100 10.10.0.10
```
다음 5분 경계(:00, :05, …)에 파일이 넘어가면 다음 순서로 진행된다.
1. 수집: 파일이 `data/live/inbox`에 들어온다.
2. 감시 프로그램(30초 주기): 저장과 Zeek.
3. 다시 계산: 약 3분.
4. 에이전트: 사건이 있으면 템플릿 알림이 먼저 나가고, 이어서 LLM 보고서가 나온다.

**배포 VM**(`~/zeek_AD`, `DC` 다시 설정):
```bash
$DC logs --tail 20 pipeline                    # "lab-YYYYMMDD: 다시 계산 종료 코드 0", "에이전트 종료 코드 0"
ls data/live/store/                            # lab-<오늘 UTC 날짜>/
curl -s 127.0.0.1:8000/api/v1/jobs | head -c 300
```
본격적인 공격 시나리오와 결과 해석은 다음 단계에서 한다.

## 모델 교체·롤백(단계 7)
결합 묶음은 MLflow Registry `zeekad-fusion`의 버전이고, 채점은 alias `champion`이 가리키는 버전을 작업 시작 때 번호로 고정해 쓴다. 기록은 [단계 7 진행 기록](stage-7-progress.md).
```bash
# 이 PC: 묶음 만들기(CIC 다섯 캡처 재현 검사 포함). 코드가 바뀌면 다시 만든다(worker가 코드 해시를 확인한다)
python scripts/build_bundle.py --fusion configs/models/fusion.v2.json
# 묶음 폴더(outputs/bundles/<설정 ID>/<시각>/)를 VM ~/zeek_AD 같은 경로로 옮긴 뒤, VM에서 등록
$DC --profile app exec -T pipeline python scripts/register_bundle.py outputs/bundles/fusion_v2/<시각>
# 승격·롤백: alias만 옮긴다. 실행 중인 작업은 그대로, 다음 채점 작업부터 바뀐다
$DC --profile app exec -T pipeline python scripts/register_bundle.py --set-alias champion 3
# 실제 추론 버전 확인(DB에 쓰지 않음): 같은 입력으로 만든 작업과 비교
$DC --profile app exec -T pipeline python scripts/check_bundle.py --capture lab-YYYYMMDD --compare-job <작업> \
    --inputs outputs/live/runs/lab-YYYYMMDD/<리비전>/worker-inputs.json
```
- 배포 순서: DB migration → 코드 이미지 → 묶음 등록·alias. 묶음 코드 파일(`zeek_ad/bundle.py`·`fusion.py`·`evaluation.py` 등)을 바꿔 올리면 지금 champion이 거부되므로 같은 코드로 만든 묶음을 먼저 등록하고 alias를 옮긴다.

## 끄고 켜기
- 끌 때: 배포 VM에서 `sudo poweroff`(또는 VMware `VM → Power → Shut Down Guest`). 전원 끄기(`Power Off`)는 DB가 정리되지 않은 채 꺼지므로 쓰지 않는다.
- 켤 때: VM을 켜면 Docker 서비스가 스스로 올라온다. `ssh zeekad-vm` → `cd ~/zeek_AD` → `DC=…` → `$DC --profile app ps`로 확인한다.

## 알아 둘 한계
- 파일이 올 때마다 그날 전체를 새 리비전 폴더로 다시 계산한다(하나 약 84MB, 대부분 그래프). 다시 계산이 성공하면 그날 리비전 중 최신 성공 2개(`keep_revisions`)와 그보다 새로운 것만 남기고 지운다. 지난 날짜는 `$DC --profile app exec -T pipeline python scripts/prune_revisions.py --dry-run`으로 보고, `--dry-run`을 빼면 지운다. 결과는 DB에 남는다([단계 6 진행 기록](stage-6-progress.md) 스물한째 작업).
- 다시 계산은 그날 파일 수에 비례해 길어진다(지금은 Spark를 띄우는 시간이 대부분).
- 모델은 CIC 월요일로 학습했다. 실습망 점수는 그 기준과의 차이로 읽는다(재학습하지 않음, Q44).
