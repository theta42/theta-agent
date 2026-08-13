#compdef theta-agent

_theta_agent() {
    local -a cmds services
    cmds=(
        'register:Register a service as a child of this host'
        'unregister:Remove a registered service'
        'list-services:List registered services'
        'install-completions:Install shell tab-completion'
        'get-secret:Fetch a single secret value'
        'get-secrets:Fetch all host/resource secrets'
        'update:Self-update binary'
        'reinitialize:Reset enrollment credentials'
        'install-service:Register the agent as a Windows service'
        'remove-service:Unregister the agent Windows service'
        'configure-login:Wire OpenCredential to the agent LDAP tunnel'
        'version:Show version'
        'help:Show help'
    )

    if (( CURRENT == 2 )); then
        _describe 'command' cmds
        return
    fi

    case "$words[2]" in
        register|unregister)
            if (( CURRENT == 3 )); then
                _values 'service type' 'systemd' 'docker' 'podman' 'process' 'systemd-timer' 'cron' 'lxc' 'kvm' 'libvirt'
                return
            fi
            if (( CURRENT == 4 )); then
                case "$words[3]" in
                    systemd)       services=(${(f)"$(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{sub(/\.service$/,"",$1); print $1}')"}) ;;
                    docker)        services=(${(f)"$(docker ps -a --format '{{.Names}}' 2>/dev/null)"}) ;;
                    podman)        services=(${(f)"$(podman ps -a --format '{{.Names}}' 2>/dev/null)"}) ;;
                    process)       services=(${(f)"$(ps -eo comm= 2>/dev/null | sort -u)"}) ;;
                    systemd-timer) services=(${(f)"$(systemctl list-timers --no-legend --no-pager 2>/dev/null | awk '{print $NF}' | sed 's/\.timer$//')"}) ;;
                    cron)          services=(${(f)"$(ls /etc/cron.d 2>/dev/null)"}) ;;
                    lxc)           services=(${(f)"$(lxc-ls -1 2>/dev/null)"}) ;;
                    kvm|libvirt)   services=(${(f)"$(virsh list --all --name 2>/dev/null)"}) ;;
                esac
                _describe 'service' services
                return
            fi
            ;;
    esac
}

_theta_agent "$@"
