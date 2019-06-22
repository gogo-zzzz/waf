function log_main()
    if config_log_cc_check == "on" then
        local STATUS = ngx.status
        log_record_status('log_main() check ',ngx.var.request_uri,"-","-",STATUS)
        -- if STATUS == ngx.HTTP_NOT_FOUND || STATUS == ngx.HTTP_BAD_REQUEST || STATUS == ngx.HTTP_UNAUTHORIZED || STATUS == ngx.HTTP_NOT_ALLOWED then
        if (STATUS >= ngx.HTTP_NOT_FOUND and STATUS <
            ngx.HTTP_INTERNAL_SERVER_ERROR) then
            local ATTACK_URI = ngx.var.uri
            local CC_TOKEN = get_client_ip() .. ATTACK_URI
            local limit = ngx.shared.limit
            CCcount = tonumber(string.match(config_cc_rate, '(.*)/'))
            CCseconds = tonumber(string.match(config_cc_rate, '/(.*)'))
            local req, _ = limit:get(CC_TOKEN)
            if req then
                if req > CCcount then
                    log_record_status('log main 4xx attack', ngx.var.request_uri, "-", "-", STATUS)
                    if config_waf_enable == "on" then
                        ngx.exit(403)
                    end
                else
                    limit:incr(CC_TOKEN, 1)
                end
            else
                limit:set(CC_TOKEN, 1, CCseconds)
            end
        end
    end
    return false
end

log_main()
