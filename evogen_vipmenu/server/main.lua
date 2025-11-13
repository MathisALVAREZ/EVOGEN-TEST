local ESX = exports['es_extended']:getSharedObject()
local playerActions = {}

local tierIndex = {}
for i, tier in ipairs(Config.TierOrder) do
    tierIndex[tier] = i
end

local function normalizeTier(tier)
    if not tier then return Config.DefaultTier end
    tier = tier:lower()
    if Config.Tiers[tier] then
        return tier
    end
    return Config.DefaultTier
end

local function parseTimestamp(timestamp)
    if not timestamp then return nil end
    if Config.TimestampIsMilliseconds then
        timestamp = math.floor(timestamp / 1000)
    end
    return timestamp
end

local function formatRemaining(seconds)
    if not seconds then
        return Config.Locale.no_subscription
    end

    local abs = math.abs(seconds)
    local days = math.floor(abs / 86400)
    local hours = math.floor((abs % 86400) / 3600)
    local minutes = math.floor((abs % 3600) / 60)

    local text = string.format('%d j %02dh%02d', days, hours, minutes)
    if seconds < 0 then
        return string.format(Config.Locale.expired, text)
    end

    return text
end

local function buildTierPayload(activeTier)
    local payload = {}
    local accessibleActions = {}
    local playerTierIndex = tierIndex[activeTier] or 1

    for _, tierName in ipairs(Config.TierOrder) do
        local tierData = Config.Tiers[tierName] or {}
        local isAccessible = (tierIndex[tierName] or 1) <= playerTierIndex
        local actions = {}

        if tierData.actions then
            for _, action in ipairs(tierData.actions) do
                actions[#actions + 1] = {
                    id = action.id,
                    label = action.label,
                    description = action.description,
                    icon = action.icon or tierData.icon
                }

                if isAccessible and action.id then
                    accessibleActions[action.id] = action
                end
            end
        end

        payload[#payload + 1] = {
            name = tierName,
            label = tierData.label or tierName,
            description = tierData.description or '',
            accent = tierData.accent or '#ffffff',
            highlight = tierData.highlight or '#111111',
            icon = tierData.icon or 'fa-solid fa-star',
            accessible = isAccessible,
            actions = actions
        }
    end

    return payload, accessibleActions
end

local function fetchVipData(source)
    local xPlayer = ESX.GetPlayerFromId(source)
    if not xPlayer then return nil end

    local identifier = xPlayer.identifier or xPlayer.getIdentifier()
    if not identifier then return nil end

    local nameResult = MySQL.single.await('SELECT firstname, lastname FROM users WHERE identifier = ? LIMIT 1', {
        identifier
    })

    local vipResult = MySQL.single.await('SELECT activepass, purchaseday, coin, activepassuntil FROM mvip WHERE identifier = ? LIMIT 1', {
        identifier
    })

    local tier = normalizeTier(vipResult and vipResult.activepass or Config.DefaultTier)
    local coins = vipResult and vipResult.coin or 0
    local expiry = parseTimestamp(vipResult and vipResult.activepassuntil)

    local remaining = expiry and (expiry - os.time()) or nil

    local tiersPayload, accessibleActions = buildTierPayload(tier)
    playerActions[source] = accessibleActions

    local fullName
    if nameResult then
        local composed = string.format('%s %s', nameResult.firstname or '', nameResult.lastname or '')
        composed = composed:gsub('%s+', ' ')
        fullName = string.trim(composed)
    end

    local payload = {
        player = {
            name = (fullName and fullName ~= '') and fullName or xPlayer.getName(),
            coins = coins,
            tier = tier,
            tierLabel = Config.Tiers[tier] and Config.Tiers[tier].label or tier,
            expiresAt = expiry and os.date('%d/%m/%Y %H:%M', expiry) or Config.Locale.no_subscription,
            remaining = formatRemaining(remaining)
        },
        tiers = tiersPayload
    }

    return payload
end

ESX.RegisterServerCallback('evogen_vipmenu:getVipData', function(source, cb)
    cb(fetchVipData(source))
end)

RegisterNetEvent('evogen_vipmenu:triggerAction', function(actionId)
    local src = source
    local actions = playerActions[src]
    if not actions or not actionId or not actions[actionId] then
        TriggerClientEvent('evogen_vipmenu:notify', src, Config.Locale.action_denied)
        return
    end

    local action = actions[actionId]
    if action.type == 'client' then
        TriggerClientEvent(action.event, src, action)
    else
        TriggerEvent(action.event, src, action)
    end

    TriggerClientEvent('evogen_vipmenu:notify', src, Config.Locale.action_success)
end)

AddEventHandler('playerDropped', function()
    playerActions[source] = nil
end)

-- Helpers
string.trim = string.trim or function(str)
    return (str:gsub('^%s*(.-)%s*$', '%1'))
end
