fx_version 'cerulean'
game 'gta5'

lua54 'yes'

shared_scripts {
    '@oxmysql/lib/MySQL.lua',
    'config.lua'
}

client_scripts {
    'client/main.lua'
}

server_scripts {
    'server/main.lua'
}

ui_page 'html/index.html'

files {
    'html/index.html',
    'html/style.css',
    'html/script.js'
}
