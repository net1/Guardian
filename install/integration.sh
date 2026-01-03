#!/bin/bash

# Source all integration modules dynamically
if [ -d "${INSTALLER_DIR}/install/integrations" ]; then
    for f in "${INSTALLER_DIR}/install/integrations"/*.sh; do
        [ -f "$f" ] && source "$f"
    done
fi

offer_filter_integration() {
    if [ "${OFFER_FILTER_INTEGRATION}" != "1" ]; then
        log_info "Skipping mail filter integration (disabled by option/env)."
        return 0
    fi

    local integrations_dir="${INSTALLER_DIR}/install/integrations"
    local available_ids=()
    local available_names=()
    
    # Scan for available integrations
    # We assume they are already sourced, so we just check the functions exist
    # But we need the IDs. We can re-scan the directory to get IDs.
    
    for f in "${integrations_dir}"/*.sh; do
        [ -f "$f" ] || continue
        local id
        id=$(basename "$f" .sh)
        
        # Check availability function
        local check_func="check_${id}_available"
        if command_exists "$check_func"; then
            if "$check_func"; then
                available_ids+=("$id")
                local name="$id"
                local name_func="get_${id}_name"
                if command_exists "$name_func"; then
                    name=$("$name_func")
                fi
                available_names+=("$name")
            fi
        fi
    done

    if [ ${#available_ids[@]} -eq 0 ]; then
        log_info "No supported mail filter detected (or all disabled). Skipping integration guidance."
        return 0
    fi

    echo -e "\n--------------------------------------------------"
    log_info "Mail Filter Integration"
    echo "--------------------------------------------------"
    log_info "Select the integrations you want to configure:"

    # Default: all selected
    local selected_indices=()
    for i in "${!available_ids[@]}"; do
        selected_indices+=("1")
    done

    while true; do
        echo
        for i in "${!available_ids[@]}"; do
            local mark=" "
            [ "${selected_indices[$i]}" == "1" ] && mark="x"
            echo "$((i+1))) [$mark] ${available_names[$i]}"
        done
        echo "d) Done (Proceed with selected)"
        echo "q) Quit (Skip all)"

        read -r -p "Toggle option (1-${#available_ids[@]}) or 'd' to done: " choice
        
        if [[ "$choice" == "d" ]]; then
            break
        elif [[ "$choice" == "q" ]]; then
            return 0
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#available_ids[@]}" ]; then
            local idx=$((choice-1))
            if [ "${selected_indices[$idx]}" == "1" ]; then
                selected_indices[$idx]="0"
            else
                selected_indices[$idx]="1"
            fi
        else
            log_error "Invalid option."
        fi
    done

    # Execute selected integrations
    for i in "${!available_ids[@]}"; do
        if [ "${selected_indices[$i]}" == "1" ]; then
            local id="${available_ids[$i]}"
            local func="configure_${id}_integration"
            if command_exists "$func"; then
                "$func"
            else
                log_error "Configuration function $func not found for $id"
            fi
        fi
    done
}

post_start_flow() {
    wait_for_status_ready "http://localhost:1133/status" 30 || true
    offer_filter_integration
}
