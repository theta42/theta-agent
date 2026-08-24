#compdef theta-agent

_theta_agent() {
    local -a cmds services
    cmds=(
        'register:Register a service on this host into the Directory'
        'unregister:Remove a registered service from the Directory'
        'list-services:List the services registered on this host'
        'get-secret:Fetch one secret value from OpenBao'
        'get-secrets:Fetch every secret this host may read'
        'verify:Check that this hosts configuration and keys are usable'
        'config-set:Merge settings into agent.yml'
        'reinitialize:Reset enrolment credentials and register again'
        'discover:List theta-suite sites announced on this network'
        'update:Self-update this binary from the Directory'
        'install-completions:Install bash/zsh tab-completion'
        'install-service:(Windows) register the agent as a service'
        'remove-service:(Windows) unregister the agent service'
        'configure-login:(Windows) wire OpenCredential to the LDAP tunnel'
        'version:Show version information'
        'help:Show help; help <command> for one command in detail'
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
