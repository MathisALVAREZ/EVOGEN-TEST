# evogen_vipmenu

Un menu VIP compact pour ESX Legacy (oxmysql) avec 4 grades : Golden, Diamond, Platinum et Secret. Les joueurs peuvent l'ouvrir via une commande ou une touche.

## Installation

1. Copiez le dossier `evogen_vipmenu` dans vos ressources (par exemple `resources/[local]/`).
2. Ajoutez la ressource dans votre `server.cfg` :
   ```cfg
   ensure evogen_vipmenu
   ```
3. Vérifiez que `oxmysql` est lancé avant la ressource et que vous êtes sous ESX Legacy.

## Commande et touche

- Commande : `/vipmenu` (modifiez `Config.CommandName`).
- Touche par défaut : `F6` (modifiable dans `Config.DefaultKey`).

## Configuration

Toutes les options sont dans `config.lua` :
- `Config.TimestampIsMilliseconds` : passez à `true` si `mvip.activepassuntil` est stocké en millisecondes.
- `Config.Tiers` : personnalisez l'apparence, la description et les actions pour chaque grade.
- Ajoutez/Supprimez des actions en gardant un `id` unique et le type (`client` ou `server`).

Lorsqu'un joueur clique sur une action, la ressource vérifie qu'elle fait partie de son grade puis :
- `type = 'client'` : `TriggerClientEvent(action.event, playerId, action)`.
- `type = 'server'` : `TriggerEvent(action.event, playerId, action)`.

Implémentez les évènements (ex. `evogen_vipmenu:spawnVipVehicle`) dans vos propres scripts pour donner les récompenses.

## Base de données

La ressource lit automatiquement :
- `users.firstname` et `users.lastname` pour afficher Nom/Prénom.
- `mvip.activepass`, `mvip.coin`, `mvip.activepassuntil` pour récupérer le grade, les coins et la durée restante.

Si aucun abonnement n'est trouvé, la ressource appliquera `Config.DefaultTier`.

## Personnalisation UI

Les fichiers NUI se trouvent dans `html/` :
- `index.html` : structure.
- `style.css` : couleurs, tailles.
- `script.js` : logique dynamique.

Libre à vous d'ajuster les couleurs pour coller à votre charte graphique.
