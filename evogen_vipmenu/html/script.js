const body = document.body;
const nameEl = document.getElementById('player-name');
const coinsEl = document.getElementById('player-coins');
const tierEl = document.getElementById('player-tier');
const remainingEl = document.getElementById('player-remaining');
const expirationEl = document.getElementById('player-expiration');
const tiersContainer = document.getElementById('tiers-container');
const closeBtn = document.getElementById('close-btn');

closeBtn.addEventListener('click', () => {
    fetch(`https://${GetParentResourceName()}/close`, { method: 'POST', body: '{}' });
});

document.addEventListener('keyup', (event) => {
    if (event.key === 'Escape') {
        fetch(`https://${GetParentResourceName()}/close`, { method: 'POST', body: '{}' });
    }
});

const setTierCards = (tiers) => {
    tiersContainer.innerHTML = '';

    tiers.forEach((tier) => {
        const card = document.createElement('div');
        card.className = `tier-card ${tier.accessible ? '' : 'locked'}`;

        const header = document.createElement('div');
        header.className = 'tier-header';

        const icon = document.createElement('div');
        icon.className = 'tier-icon';
        icon.style.background = tier.accent;
        icon.innerHTML = `<i class="${tier.icon}"></i>`;

        const label = document.createElement('span');
        label.textContent = tier.label;

        header.appendChild(icon);
        header.appendChild(label);

        const description = document.createElement('p');
        description.className = 'tier-description';
        description.textContent = tier.description;

        const actionList = document.createElement('div');
        actionList.className = 'action-list';

        if (tier.actions.length === 0) {
            const empty = document.createElement('p');
            empty.className = 'tier-description';
            empty.textContent = 'Aucune action configurée.';
            actionList.appendChild(empty);
        } else {
            tier.actions.forEach((action) => {
                const button = document.createElement('button');
                button.className = `action-button ${tier.accessible ? '' : 'disabled'}`;
                button.type = 'button';

                const actionIcon = document.createElement('span');
                actionIcon.className = 'tier-icon';
                actionIcon.style.background = tier.accent;
                actionIcon.innerHTML = `<i class="${action.icon || 'fa-solid fa-star'}"></i>`;

                const content = document.createElement('div');
                content.className = 'action-content';

                const title = document.createElement('h4');
                title.textContent = action.label;

                const desc = document.createElement('p');
                desc.textContent = action.description;

                content.appendChild(title);
                content.appendChild(desc);

                button.appendChild(actionIcon);
                button.appendChild(content);

                if (tier.accessible) {
                    button.addEventListener('click', () => {
                        fetch(`https://${GetParentResourceName()}/triggerAction`, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json; charset=UTF-8'
                            },
                            body: JSON.stringify({ id: action.id })
                        });
                    });
                }

                actionList.appendChild(button);
            });
        }

        card.appendChild(header);
        card.appendChild(description);
        card.appendChild(actionList);
        card.style.border = `1px solid ${tier.accessible ? tier.accent : 'var(--border)'}`;

        tiersContainer.appendChild(card);
    });
};

const handleOpen = (data) => {
    if (!data) return;
    nameEl.textContent = data.player.name;
    coinsEl.textContent = data.player.coins;
    tierEl.textContent = data.player.tierLabel;
    remainingEl.textContent = data.player.remaining;
    expirationEl.textContent = data.player.expiresAt;
    setTierCards(data.tiers);
    body.classList.add('visible');
};

window.addEventListener('message', (event) => {
    const { action, data } = event.data;

    switch (action) {
        case 'open':
            handleOpen(data);
            break;
        case 'close':
            body.classList.remove('visible');
            break;
    }
});
