#!/bin/bash
# File              : codius-install.sh
# Author            : N3TC4T <netcat.av@gmail.com>
# Date              : 16.06.2018
# Last Modified Date: 05.07.2020
# Last Modified By  : wilsonianb <brandon@coil.com>
# Copyright (c) 2018 N3TC4T <netcat.av@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set -e

########## Variable ##########
SUDO=""
BASH_C="bash -c"
CURL_C="curl -SL -o"
LOG_OUTPUT="/tmp/${0##*/}$(date +%Y-%m-%d.%H-%M)"
CURRENT_USER="$(id -un 2>/dev/null || true)"
BASE_DIR=$(cd "$(dirname "$0")"; pwd); cd ${BASE_DIR}
INSTALLER_BRANCH="master"
INSTALLER_URL="https://raw.githubusercontent.com/codius/codius-install/${INSTALLER_BRANCH}/codius-install.sh"
K8S_MANIFEST_PATH="https://raw.githubusercontent.com/codius/codius-install/${INSTALLER_BRANCH}/manifests"
########## k3s ##########
K3S_VERSION="v1.18.6+k3s1"
K3S_INSTALL_URL="https://raw.githubusercontent.com/rancher/k3s/${K3S_VERSION}/install.sh"
K3S_TRAEFIK_URL="https://raw.githubusercontent.com/rancher/k3s/${K3S_VERSION}/manifests/traefik.yaml"
########## Calico ##########
CALICO_BASE="github.com/codius/codius-install/manifests/calico?ref=${INSTALLER_BRANCH}"
########## Cert-manager ##########
CERT_MANAGER_BASE="github.com/codius/codius-install/manifests/cert-manager?ref=${INSTALLER_BRANCH}"
########## Constant ##########
#Color Constant
RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
WHITE=`tput setaf 7`
LIGHT=`tput bold `
RESET=`tput sgr0`
#Error Message#Error Message
ERR_ROOT_PRIVILEGE_REQUIRED=(10 "This install script needs root privilege, please retry using 'sudo' or root user!")
ERR_NOT_PUBLIC_IP=(11 "You need a public IP to run Codius!")
ERR_NOT_SUPPORT_DISTRO=(21 "Sorry, the installer only supports centos/ubuntu/debian/fedora.")
ERR_UNKNOWN_MSG_TYPE=98
ERR_UNKNOWN=99
# Helpers ==============================================

display_header()
{
cat <<"EOF"

     ____          _ _             ___           _        _ _           
    / ___|___   __| (_)_   _ ___  |_ _|_ __  ___| |_ __ _| | | ___ _ __ 
   | |   / _ \ / _` | | | | / __|  | || '_ \/ __| __/ _` | | |/ _ \ '__|
   | |__| (_) | (_| | | |_| \__ \  | || | | \__ \ || (_| | | |  __/ |   
    \____\___/ \__,_|_|\__,_|___/ |___|_| |_|___/\__\__,_|_|_|\___|_|   


This script will let you set up your own Codius host in minutes,
even if you haven't used Codius before.
It has been designed to be as unobtrusive and universal as possible.

EOF
}

_box () {
    str="$@"
    len=$((${#str}+4))
    for i in $(seq $len); do echo -n '.'; done;
    echo; echo ". "$str" .";
    for i in $(seq $len); do echo -n '.'; done;
    echo
}

function spin_wait() { 
  local -r SPIN_DELAY="0.1"
  local spinstr="⠏⠛⠹⠼⠶⠧"
  printf "  "
  while kill -0 $1 2>/dev/random; do
    local tmp=${spinstr#?}

    if [ -z "$2" ]; then
        printf " \b\b\b${tmp:0:1} "
    else
        printf "${cl} ${tmp:0:1} ${2}"
    fi

    local spinstr=$tmp${spinstr%"$tmp"}
    sleep ${SPIN_DELAY}
  done
  printf "\033[3D\033[K ${LIGHT}${GREEN}✓ ${RESET}"
  # printf "\r\033[K"
}

function _exec() {
  local -i PID=
  local COMMAND=$1
  shift      ## Clip the first value of the $@, the rest are the options. 
  local COMMAND_OPTIONS="$@"
  local COMMAND_OUTPUT=""
  echo -e "\n==================================" >> "${LOG_OUTPUT}"
  echo "${COMMAND} $COMMAND_OPTIONS" >> "${LOG_OUTPUT}"
  echo -e "==================================\n" >> "${LOG_OUTPUT}"
  exec 3>$(tty)
  eval "time ${SUDO} bash -c '${COMMAND} ${COMMAND_OPTIONS}'" >>"${LOG_OUTPUT}" 2>&1  &
  PID=$! # Set global PGID to process id of the command we just ran. 
  spin_wait "${PID}"
  exec 3>&-

  if ! wait ${PID};then
    show_message error "An error occurred. See ${LOG_OUTPUT}"
    exit ${ret}
  fi
}

function program_is_installed {
  # set to 1 initially
  local return_=1
  # set to 0 if not found
  type $1 >/dev/null 2>&1 || { local return_=0; }
  # return value
  echo "$return_"
}

function service_is_running {
  # set to 1 initially
  local return_=0
  # set to 0 if not found
  if (( $(ps -ef | grep -v grep | grep $1 | wc -l) > 0 )) ;then
    local return_=1
  fi
  # return value
  echo "$return_"
}

function echo_if {
  if [ $1 == 1 ]; then
    echo -e "${LIGHT}${GREEN}✔ ${RESET}"
  else
    echo -e "${RED}✘${RESET}"
  fi
}

new_line() { printf "\n"; }

show_message() {
  case "$1" in
    debug)  echo -e "\n[${BLUE}DEBUG${RESET}] : $2";;
    info)   echo -e -n "\n${WHITE}$2${RESET}" ;;
    warn)   echo -e    "\n[${YELLOW}WARN${RESET}] : $2" ;;
    done|success) echo -e "${LIGHT}${GREEN}$2${RESET}" ;;
    error|failed) echo -e "\n[${RED}ERROR${RESET}] : $2" ;;
  esac
}

command_exist() {
  type "$@" > /dev/null 2>&1
}

check_user() {
  if [[ "${CURRENT_USER}" != "root" ]];then
    if (command_exist sudo);then
      SUDO='sudo'
    else
      show_message error "${ERR_ROOT_PRIVILEGE_REQUIRED[1]}" && exit ${ERR_ROOT_PRIVILEGE_REQUIRED[0]}
    fi
    show_message info "${WHITE}Hint: This installer needs root privilege\n"
    ${SUDO} echo -e "\n"
  fi
}

install_update_k3s() {
  ${SUDO} ${CURL_C} /tmp/k3s-install.sh ${K3S_INSTALL_URL} >>"${LOG_OUTPUT}" 2>&1 && ${SUDO} chmod a+x /tmp/k3s-install.sh
  ${SUDO} ${CURL_C} /var/tmp/authentication-token-webhook-config.yaml "${K8S_MANIFEST_PATH}/authentication-token-webhook-config.yaml" >>"${LOG_OUTPUT}" 2>&1
  sed -i s/codius.example.com/$HOSTNAME/g /var/tmp/authentication-token-webhook-config.yaml
  _exec bash /tmp/k3s-install.sh \
    --cluster-cidr=192.168.0.0/16 \
    --flannel-backend=none \
    --disable-network-policy \
    --disable traefik \
    --kube-apiserver-arg authentication-token-webhook-config-file=/var/tmp/authentication-token-webhook-config.yaml \
    --kube-apiserver-arg authentication-token-webhook-cache-ttl=0s
  until kubectl get node > /dev/null 2>&1 || (( k3s_count++ >= 60 ))
  do
    sleep 1
  done
  _exec kubectl apply -k $CALICO_BASE
  _exec kubectl rollout status ds -n kube-system calico-node

  ${SUDO} ${CURL_C} /tmp/traefik.yaml $K3S_TRAEFIK_URL >>"${LOG_OUTPUT}" 2>&1
  # Allow ingress for kube apiserver
  # Manually add traefik helm config and run k3s with --disable traefik
  # Otherwise, restarting k3s reverts changes to the traefik helm config
  sed -i '/ssl:/a \      insecureSkipVerify: true' /tmp/traefik.yaml
  _exec cp /tmp/traefik.yaml /var/lib/rancher/k3s/server/manifests/traefik-mod.yaml
  _exec kubectl wait --for=condition=Available -n kube-system deployment/coredns
  until kubectl get job -n kube-system helm-install-traefik > /dev/null 2>&1 || (( traefik_count++ >= 60 ))
  do
    sleep 1
  done
  _exec kubectl wait --for=condition=complete --timeout=300s -n kube-system job/helm-install-traefik
  _exec kubectl wait --for=condition=Available -n kube-system deployment/traefik
}

install_update_kata() {
  _exec kubectl apply -k github.com/kata-containers/packaging/kata-deploy/kata-rbac/base
  _exec kubectl apply -k github.com/kata-containers/packaging/kata-deploy/kata-deploy/overlays/k3s
  _exec kubectl rollout status ds -n kube-system kata-deploy
  # wait for k3s to restart
  while kubectl logs --selector=name=kata-deploy -n kube-system -f > /dev/null 2>&1; do true; done
  until kubectl get node > /dev/null 2>&1 || (( count++ >= 60 ))
  do
    sleep 1
  done
  _exec kubectl apply -f https://raw.githubusercontent.com/kata-containers/packaging/master/kata-deploy/k8s-1.14/kata-qemu-runtimeClass.yaml
}

install_update_acme_dns() {
  local ACME_DNS_DIR=`mktemp -d -t acmedns.XXXX`
  ${SUDO} ${CURL_C} $ACME_DNS_DIR/kustomization.yaml "${K8S_MANIFEST_PATH}/acme-dns/kustomization.yaml" >>"${LOG_OUTPUT}" 2>&1
  ${SUDO} ${CURL_C} $ACME_DNS_DIR/kustomizeconfig.yaml "${K8S_MANIFEST_PATH}/acme-dns/kustomizeconfig.yaml" >>"${LOG_OUTPUT}" 2>&1
  ${SUDO} ${CURL_C} $ACME_DNS_DIR/acme_dns_config_patch.yaml "${K8S_MANIFEST_PATH}/acme-dns/acme_dns_config_patch.yaml" >>"${LOG_OUTPUT}" 2>&1
  tee $ACME_DNS_DIR/config.env << EOF > /dev/null
hostname=$HOSTNAME
ip_address=$IP
EOF
  _exec kubectl apply -k $ACME_DNS_DIR
  _exec kubectl wait --for=condition=Available --timeout=60s -n acme-dns deployment/acme-dns
}

install_update_cert_manager() {
  _exec kubectl apply -k $CERT_MANAGER_BASE
  _exec kubectl wait --for=condition=Available -n cert-manager deployment/cert-manager
  _exec kubectl wait --for=condition=Available -n cert-manager deployment/cert-manager-webhook
}

install_update_codius() {
  mkdir -p /tmp/codius
  ${SUDO} ${CURL_C} /tmp/codius/kustomization.yaml "${K8S_MANIFEST_PATH}/codius/kustomization.yaml" >>"${LOG_OUTPUT}" 2>&1
  ${SUDO} ${CURL_C} /tmp/codius/ingress.yaml "${K8S_MANIFEST_PATH}/codius/ingress.yaml" >>"${LOG_OUTPUT}" 2>&1
  tee /tmp/codius/config.env << EOF > /dev/null
hostname=$HOSTNAME
host_url=https://$HOSTNAME
payment_pointer_url=$PAYMENT_POINTER
proxy_payment_pointer=\$$HOSTNAME
EOF
  _exec kubectl apply -k /tmp/codius
  _exec kubectl wait --for=condition=Available -n codius-system deployment/codius-auth
  _exec kubectl wait --for=condition=Available -n codius-system deployment/codius-web
  _exec kubectl wait --for=condition=Available -n codius-system deployment/receipt-verifier
  _exec kubectl wait --for=condition=Available -n codius-system deployment/codius-operator-controller-manager
}

# ============================================== Helpers


################### INSTALL ###########################

install()
{

  new_line
  show_message info "[-] I need to ask you a few questions before starting the setup."
  show_message info "[-] You can leave the default options and just press enter if you are ok with them."
  new_line
  new_line

  # checks for script
  check_user

  # Server Ip Address
  echo "[+] First, provide the IPv4 address of the network interface"
  # Autodetect IP address and pre-fill for the user
  IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
  read -p "IP address: " -e -i $IP IP
  # If $IP is a private IP address, the server must be behind NAT
  if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
    show_message error "${ERR_NOT_PUBLIC_IP[1]}"
    exit "${ERR_NOT_PUBLIC_IP[0]}"
  fi

  # Hostname
  echo "[+] What is your Codius hostname?"
  read -p "Hostname: " -e -i `uname -n` HOSTNAME
  if [[ -z "$HOSTNAME" ]]; then
    show_message error "No Hostname entered, exiting..."
    exit 0
  fi

  # Existing SSL certificate
  echo "[+] What is the file path for your SSL certificate? Leave blank to auto-generate certificate."
  while true; do
    read -p "Filepath: " -e CERTFILE

    if [[ -z "$CERTFILE" ]] || [[ -e "$CERTFILE" ]]; then
      break
    else
      show_message error "Invalid file path entered, try again..."
    fi
  done

  if [[ -z "$CERTFILE" ]]; then
    # Email for certbot
    echo "[+] What is your email address?"
    while true; do
      read -p "Email: " -e EMAIL

      if [[ -z "$EMAIL" ]] || ! [[ "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$ ]]; then
          show_message error "Invalid email entered, try again..."
      else
        break
      fi
    done
  else
    # SSL key
    echo "[+] What is the file path for your SSL key?"
    while true; do
      read -p "Filepath: " -e KEYFILE

      if [[ -e "$KEYFILE" ]]; then
        break
      else
        show_message error "Invalid file path entered, try again..."
      fi
    done
  fi

  # Payment pointer
  echo "[+] What is your payment pointer URL?"
  read -p "Payment pointer URL: " -e PAYMENT_POINTER
  if [[ -z "$PAYMENT_POINTER" ]]; then
    show_message error "No payment pointer URL entered, exiting..."
    exit 0
  fi

  # Set hostname
  ${SUDO} hostnamectl set-hostname $HOSTNAME

  # Subdomain DNS ==============================================
  new_line
  show_message info "[+] Please create two A records within your domain DNS like the examples below:"
  new_line
  cat <<EOF
------------------------------------------------------------

$HOSTNAME.      300     IN      A       $IP
*.$HOSTNAME.    300     IN      A       $IP

------------------------------------------------------------
EOF

  read -n1 -r -p "Press any key to continue..."

  while true; do
    if ping -c1 -W1 ping.$HOSTNAME &> /dev/null; then
      break
    else
      show_message warn "It looks like the $HOSTNAME cannot be resolved yet, waiting 30s... "
    fi
    sleep 30 #check again in SLEEP seconds
  done

  # ============================================== Subdomain DNS

  # git ====================================

  show_message info "[+] Installing git..."

  if (command_exist yum);then
    _exec "yum install -y git"
  elif (command_exist apt-get);then
    _exec "apt-get install -y git"
  else
    show_message error "${ERR_NOT_SUPPORT_DISTRO[1]}" && exit ${ERR_NOT_SUPPORT_DISTRO[0]}
  fi

  # ============================================== git

  # Kubernetes ==============================================

  show_message info "[+] Installing k3s with Calico CNI... "
  install_update_k3s

  show_message info "[+] Installing Kata Containers... "
  install_update_kata

  # ============================================== Kubernetes

  # Certificate ==============================================

  show_message info "[+] Installing cert-manager... "
  install_update_cert_manager

  _exec kubectl create namespace codius
  _exec kubectl create namespace codius-system

  if [[ -z "$CERTFILE" ]]; then
    show_message info "[+] Installing acme-dns... "
    install_update_acme_dns

    show_message info "[+] Generating certificate for ${HOSTNAME}"

    # https://cert-manager.io/docs/configuration/acme/dns01/acme-dns/
    local ACME_DNS_IP=`kubectl get pods --namespace=acme-dns --selector=app=acme-dns -o jsonpath='{.items[0].status.podIP}'`
    local ACME_CREDS=`curl -sX POST http://$ACME_DNS_IP/register`
    local CERT_DIR=`mktemp -d -t codius-certs.XXXX`

    tee $CERT_DIR/acme-dns.json << EOF > /dev/null
{"$HOSTNAME": $ACME_CREDS, "*.$HOSTNAME": $ACME_CREDS}
EOF

    local ACME_FULL_DOMAIN=`sed -e 's/[{}]/''/g' $CERT_DIR/acme-dns.json | awk -v RS=',"' -F: '/^fulldomain/ {print $2; exit;}' | tr -d \"`
    new_line
    show_message info "[+] Please create an NS and CNAME record within your domain DNS like the examples below:"
    new_line
    cat <<EOF
------------------------------------------------------------

auth.$HOSTNAME.            300     IN      NS         $HOSTNAME
_acme-challenge.$HOSTNAME. 300     IN      CNAME      $ACME_FULL_DOMAIN

------------------------------------------------------------
EOF
    read -n1 -r -p "Press any key to continue..."

    show_message info "[+] Generating Let's Encrypt certificates... "
    ${SUDO} ${CURL_C} $CERT_DIR/kustomization.yaml "${K8S_MANIFEST_PATH}/letsencrypt/kustomization.yaml" >>"${LOG_OUTPUT}" 2>&1
    ${SUDO} ${CURL_C} $CERT_DIR/kustomizeconfig.yaml "${K8S_MANIFEST_PATH}/letsencrypt/kustomizeconfig.yaml" >>"${LOG_OUTPUT}" 2>&1
    ${SUDO} ${CURL_C} $CERT_DIR/issuer.yaml "${K8S_MANIFEST_PATH}/letsencrypt/issuer.yaml" >>"${LOG_OUTPUT}" 2>&1
    ${SUDO} ${CURL_C} $CERT_DIR/certificate.yaml "${K8S_MANIFEST_PATH}/letsencrypt/certificate.yaml" >>"${LOG_OUTPUT}" 2>&1
    tee $CERT_DIR/config.env << EOF > /dev/null
hostname=$HOSTNAME
email=$EMAIL
EOF
    _exec kubectl apply -k $CERT_DIR
    _exec kubectl wait --for=condition=Ready --timeout=60s -n codius-system issuer/letsencrypt
    _exec kubectl wait --for=condition=Ready --timeout=600s -n codius-system certificate/codius-host
  else
    _exec kubectl create secret tls codius-host-cert --key $KEYFILE --cert $CERTFILE --namespace codius-system
  fi

  # ============================================== Certificate

  # Codius =============================================

  show_message info "[+] Installing Codius... "
  install_update_codius

  # ============================================= Codius

  # ============================================== Finishing
  new_line
  printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' =
  new_line
  show_message done "[!] Congratulations, it looks like you installed Codius successfully!"
  new_line
  show_message done "[-] You can visit your Codius host at https://$HOSTNAME"
  show_message done "[-] For installation log visit $LOG_OUTPUT"
  show_message done "[-] You can see everything running in your Kubernetes cluster by running: kubectl get all --all-namespaces"
  new_line
  printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' =

  exit
}



################### UPDATE ###########################

update()
{
  check_user

  show_message info "[+] Updating k3s... "
  install_update_k3s

  show_message info "[+] Updating Kata Containers... "
  install_update_kata

  show_message info "[+] Updating acme-dns... "
  install_update_acme_dns

  show_message info "[+] Updating cert-manager... "
  install_update_cert_manager

  printf "\n\n"
  show_message done "[!] Everything done!"

  printf "\n\n"

  exit

}

################### CLEANUP ###########################

clean(){

  check_user

  show_message warn "This action will remove packages listed below and all configuration files belonging to them:
  \n* k3s\n* Kata Containers\n* Codius"

  new_line
  read -p "Continue Anyway? [y/N]: " -e CONTINUE

  if ! [[ "$CONTINUE" = 'y' || "$CONTINUE" = 'Y' ]]; then
    exit 0
  fi

  show_message info "[!] Stopping Codius services... "
  _exec kubectl delete services.core.codius.org --all=true
  while kubectl wait --for=delete pods -n codius --all=true > /dev/null 2>&1; do true; done

  show_message info "[!] Removing Kata Containers... "
  _exec kubectl delete -k github.com/kata-containers/packaging/kata-deploy/kata-deploy/overlays/k3s
  while kubectl wait --for=delete pod -n kube-system --selector=name=kata-deploy > /dev/null 2>&1; do true; done

  show_message info "[!] Removing k3s... "
  _exec /usr/local/bin/k3s-uninstall.sh

  printf "\n\n"
  show_message done "[*] Everything cleaned successfully!"
  printf "\n\n"

  exit 0
}


################### CHECK FOR SCRIPT UPDATES ###########################

check_script_update() {
  LATEST_FILE=$(curl "$INSTALLER_URL" 2>/dev/null) || { printf '%s\n' 'Unable to check for updates.'; curlFailed=1; }
  THIS_MOD=$(grep -m1 '# Last Modified Date: ' $0)
  LASTED_MOD=$(grep -m1 '# Last Modified Date: ' <<<"$LATEST_FILE")

  if [[ "$THIS_MOD" != "$LASTED_MOD" ]] &&  [[ ! -n "$curlFailed" ]]; then
    show_message info "[!] An update is available for the script... "
    read -p "Update Now ? [y/N]: " -e UPDATE

    if [[ "$UPDATE" = 'y' || "$UPDATE" = 'Y' ]]; then
      show_message info "[+] Updating now.\n"
      tmpfile=$(mktemp)
      chmod +x "$tmpfile"
      cat <<<"$LATEST_FILE" > "$tmpfile"
      mv "$tmpfile" "$0"
      show_message done "\n[-] Installer successfully updated to the latest version. Please restart the script to continue.\n"
      exit
    fi
  fi

  new_line

}

################### MAIN ###########################

while :
do
  clear
  display_header

  # check for script Update at startup
  check_script_update

  echo "What do you want to do?"
                  echo "   1) Install and run Codius in your system"
                  echo "   2) Cleanup Codius from the server"
                  # echo "   3) Update Codius host components to the latest versions"
                  echo "   3) Exit"
  read -p "Select an option [1-3]: " option

  case $option in
    1)install;;
    2)clean;;
    # 3)update;;
    3)exit;;
  esac
done

