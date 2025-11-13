Config = {}

-- Command/keybind settings
Config.CommandName = 'vipmenu'
Config.CommandDescription = 'Ouvrir le menu VIP'
Config.DefaultKey = 'F6'

-- Database settings
Config.TimestampIsMilliseconds = false -- change to true if mvip.activepassuntil is stored in milliseconds
Config.DefaultTier = 'golden'

-- Tiers order defines the accessibility hierarchy (higher index = higher VIP level)
Config.TierOrder = { 'golden', 'diamond', 'platinum', 'secret' }

Config.Tiers = {
    golden = {
        label = 'Golden',
        accent = '#f1c232',
        highlight = '#2e2210',
        description = 'Les basiques indispensables du VIP.',
        icon = 'fa-solid fa-crown',
        actions = {
            {
                id = 'golden_care_package',
                label = 'Pack de soin',
                description = 'Déclenche un pack médical configuré côté serveur.',
                type = 'server',
                event = 'evogen_vipmenu:goldenCarePackage'
            },
            {
                id = 'golden_announcement',
                label = 'Annonce VIP',
                description = 'Permet au joueur de déclencher une annonce stylisée.',
                type = 'client',
                event = 'evogen_vipmenu:goldenAnnouncement'
            }
        }
    },
    diamond = {
        label = 'Diamond',
        accent = '#9ad5ff',
        highlight = '#14212d',
        description = 'Avantages premium avancés.',
        icon = 'fa-solid fa-gem',
        actions = {
            {
                id = 'diamond_spawn_vehicle',
                label = 'Véhicule VIP',
                description = 'Autorise le joueur à demander un véhicule défini côté serveur.',
                type = 'server',
                event = 'evogen_vipmenu:spawnVipVehicle'
            }
        }
    },
    platinum = {
        label = 'Platinum',
        accent = '#e5e4e2',
        highlight = '#1f1f1f',
        description = 'Le confort ultime en ville.',
        icon = 'fa-solid fa-medal',
        actions = {
            {
                id = 'platinum_refresh',
                label = 'Recharge instantanée',
                description = 'Déclenchement libre, gérez la logique côté serveur.',
                type = 'server',
                event = 'evogen_vipmenu:platinumRefresh'
            }
        }
    },
    secret = {
        label = 'Secret',
        accent = '#ff4dd8',
        highlight = '#2b0e2d',
        description = 'Le cercle très fermé. Personnalisez chaque action.',
        icon = 'fa-solid fa-user-secret',
        actions = {
            {
                id = 'secret_portal',
                label = 'Accès secret',
                description = 'Interagissez avec vos scripts pour offrir une expérience unique.',
                type = 'server',
                event = 'evogen_vipmenu:secretPortal'
            }
        }
    }
}

-- Notification helpers
Config.Locale = {
    data_missing = 'Impossible de récupérer vos informations VIP.',
    action_denied = 'Action non autorisée.',
    action_success = 'Action envoyée.',
    no_subscription = 'Aucun abonnement actif.',
    expired = 'Abonnement expiré depuis %s.'
}
