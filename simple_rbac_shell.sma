/*============================================================================================
    
    ----------------------------------
    -*- Simple RBAC - server shell -*-
    ----------------------------------
    Плагин управления группами через консоль сервера

    Описание:
        Плагин предоставляет консольную реализацию для взаимодействия с Simple RBAC.
    
    
============================================================================================*/

#pragma semicolon 1;

#include <amxmodx>
#include <amxmisc>
#include <auth_core>
#include <simple_rbac>
#define is_server(%0) %0==0

/*================================= Информация о плагине ===================================*/
#define PLUG_OBJNAME            "Simple RBAC shell"
#define PLUG_VERSION            "1.0.0"
#define PLUG_CREATOR            "Boec[SpecOPs]"


/*================================= Внутренние структуры ===================================*/

enum _:RbacShellSwitch
{
    rss_add = 1,
    rss_get,
    rss_del,
    rss_help
}

enum _:RbacShellData 
{
    rsd_uid = 1,
    rsd_initiator,
    rsd_group[GROUPNAME_MAXLEN],
    rsd_date,
    rsd_switch
}


/*

rbac add [uID nickname steamid pID] [groupname] [date]
rbac get [uID nickname steamid pID] [groupname]
rbac del [uID nickname steamid pID] [groupname]

*/

/*==================================== Блок переменных =====================================*/
new shell[RbacShellData];
new blocked_bythread = false;

/*================== Первичная инициализация и завершение работы плагина ===================*/

public plugin_init()
{
    register_concmd("rbac", "shell__handler", -1, "Shell extension for RBAC plugin");
}

// Адаптивный вывод сообщений в консоль (в client_print при индексе = 1, отправит всем)
public print(id, msg[])
{
    if(id) {
        client_print(id, print_console, msg);
    } else {
        server_print(msg);
    }
}

// 
// Обработчик команд rbac
//
public shell__handler(id,level,cid)
{
    // Проверка доступа
    if(!cmd_access(id,level,cid,1))
        return PLUGIN_HANDLED;
        
    // Запросы к базе данных могут выполняться в потоке. Ожидаем конца запроса перед следующей попыткой
    if(blocked_bythread) {
        print(id, "Failed! Previous command not completed!");
        return PLUGIN_CONTINUE;
    }
 
    // Парсим данные
    new threaded = parse_shell_arguments(id);
    
    if(threaded) {
        blocked_bythread = true;
        print(id, "Executing...");
        return PLUGIN_CONTINUE;
    } else {
        shell__action();
        return PLUGIN_CONTINUE;
    }
}

//
// Метод получает данные о пользователе.
//
public auth__handler(Array:users) 
{
    new user[UserStruct];
    array_read_user(users, user);
    
    shell[rsd_uid] = user[us_user_id];
    
    shell__action();
}

//
// 
//
shell__action()
{
    print(shell[rsd_initiator], "Complete.");
    blocked_bythread = false;
    
    switch(shell[rsd_switch]) {
        case rss_add: {
            rbac_usermod(shell[rsd_uid], shell[rsd_group], ugs_expires, shell[rsd_date]);
        }
        case rss_get: {
            server_print("Not implemented yet :3");    
        }
        case rss_del: {
            rbac_deluser(shell[rsd_uid], shell[rsd_group]);
        }
        case rss_help: {
            print(shell[rsd_initiator], "Role based access control (shell) manual");
            print(shell[rsd_initiator], "Usage: rbac add -u 1 'Vip' 1d5h");
        }
    }
    
}

parse_shell_arguments(id)
{
    new args = read_argc(), temp[32], param = 0;
    new threaded = false;
    
    shell[rsd_initiator] = id;
    shell[rsd_date] = 0;
    read_argv(++param, temp, charsmax(temp));
    
    if(equali(temp, "add")) {
        shell[rsd_switch] = rss_add;
    } else if(equali(temp, "del")) {
        shell[rsd_switch] = rss_del;
    } else if(equali(temp, "get")) {
        shell[rsd_switch] = rss_get;
    } else if(equali(temp, "help")) {
        shell[rsd_switch] = rss_help;
        return false;
    } else {
        print(id, "Command not found");
        return false;
    }
    
    read_argv(++param, temp, charsmax(temp));
    
    // UserId
    if(equali(temp, "-u")) {
        threaded = false;
        shell[rsd_uid] = read_argv_int(++param);
        
    // PlayerId
    } else if(equali(temp, "-p")) {
        threaded = false;
        shell[rsd_uid] = auth_get_byplayer(read_argv_int(++param));
        
    // Nickname
    } else if(equali(temp, "-n")) {
        read_argv(++param, temp, charsmax(temp));
        auth_getuser(us_nickname, temp, "auth__handler");
        threaded = true;
    
    // SteamId
    } else if(equali(temp, "-s")) {
        read_argv(++param, temp, charsmax(temp));
        auth_getuser(us_steam, temp, "auth__handler");
        threaded = true;
    }
    
    read_argv(++param, shell[rsd_group], charsmax(shell[rsd_group]));
    
    if(param < args-1) {
        shell[rsd_date] = get_systime(read_argv_int(++param));
    }
    
    return threaded;
}




