local ESX = exports['es_extended']:getSharedObject()
local isMenuOpen = false

local function focusNui(state)
    SetNuiFocus(state, state)
    if SetNuiFocusKeepInput then
        SetNuiFocusKeepInput(false)
    end
end

local function closeMenu()
    if not isMenuOpen then return end
    isMenuOpen = false
    focusNui(false)
    SendNUIMessage({ action = 'close' })
end

RegisterNUICallback('close', function(_, cb)
    closeMenu()
    cb('ok')
end)

RegisterNUICallback('triggerAction', function(data, cb)
    if not data or not data.id then
        cb('error')
        return
    end

    TriggerServerEvent('evogen_vipmenu:triggerAction', data.id)
    cb('ok')
end)

RegisterNetEvent('evogen_vipmenu:notify', function(message)
    if ESX and message then
        ESX.ShowNotification(message)
    end
end)

local function openMenu()
    if isMenuOpen then return end

    ESX.TriggerServerCallback('evogen_vipmenu:getVipData', function(payload)
        if not payload then
            ESX.ShowNotification(Config.Locale.data_missing)
            return
        end

        isMenuOpen = true
        focusNui(true)
        SendNUIMessage({ action = 'open', data = payload })
    end)
end

RegisterCommand(Config.CommandName, function()
    if isMenuOpen then
        closeMenu()
    else
        openMenu()
    end
end, false)

RegisterKeyMapping(Config.CommandName, Config.CommandDescription, 'keyboard', Config.DefaultKey)

AddEventHandler('onResourceStop', function(resource)
    if resource ~= GetCurrentResourceName() then return end
    if isMenuOpen then
        closeMenu()
    end
end)
