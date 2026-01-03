#!/bin/bash

detect_spamassassin_paths() {
    SA_CONF_DIR=""
    SA_PLUGIN_DIR=""

    SA_CONF_DIR="$(first_existing_dir \
        "/etc/mail/spamassassin" \
        "/etc/spamassassin" \
        "/usr/local/etc/mail/spamassassin" \
        "/usr/local/etc/spamassassin" \
    )" || true

    # Try to locate Mail::SpamAssassin installation path and infer Plugin dir
    if command_exists perl; then
        local sa_pm=""
        sa_pm="$(perl -MMail::SpamAssassin -e 'print $INC{"Mail/SpamAssassin.pm"}' 2>/dev/null || true)"
        if [ -n "$sa_pm" ]; then
            # .../Mail/SpamAssassin.pm -> .../Mail/SpamAssassin/Plugin
            local base="${sa_pm%/SpamAssassin.pm}"
            SA_PLUGIN_DIR="$(first_existing_dir "${base}/SpamAssassin/Plugin")" || true
        fi
    fi

    # Common plugin install paths
    if [ -z "$SA_PLUGIN_DIR" ]; then
        SA_PLUGIN_DIR="$(first_existing_dir \
            "/usr/share/perl5/Mail/SpamAssassin/Plugin" \
            "/usr/local/share/perl5/Mail/SpamAssassin/Plugin" \
            "/usr/share/perl/5.*/Mail/SpamAssassin/Plugin" \
        )" || true
    fi
}

check_spamassassin_available() {
    if [ "${ENABLE_SPAMASSASSIN_INTEGRATION}" = "0" ]; then
        return 1
    fi
    command_exists spamassassin
}

get_spamassassin_name() {
    echo "SpamAssassin"
}

configure_spamassassin_integration() {
    detect_spamassassin_paths

    echo -e "\n--------------------------------------------------"
    log_info "SpamAssassin integration (manual steps):"
    log_info "Detected paths (best-effort):"
    echo " - SA_CONF_DIR:    ${SA_CONF_DIR:-<unknown>}"
    echo " - SA_PLUGIN_DIR:  ${SA_PLUGIN_DIR:-<unknown>}"
    echo
    echo "1) Prefer placing your Mailuminati .cf rules in: ${SA_CONF_DIR:-/etc/mail/spamassassin}"
    echo "2) If you ship a custom Perl plugin, place it in: ${SA_PLUGIN_DIR:-<perl site/lib>/Mail/SpamAssassin/Plugin}"
    echo "3) Add a custom check (plugin or wrapper) that submits the message (MIME) to: http://127.0.0.1:1133/analyze"
    echo "4) If response action==spam: add a rule hit and score accordingly."
    echo "5) Optionally forward user feedback to: http://127.0.0.1:1133/report"
    echo "6) Restart spamd/spamassassin service."
    log_info "Note: This installer currently prints guidance only (no files are written)."
    echo -e "--------------------------------------------------\n"
}
