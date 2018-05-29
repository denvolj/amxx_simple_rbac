/*============================================================================================
    
    ----------------------------------------
    -*- Simple Role Based Access Control -*-
    ----------------------------------------
    Управление доступом на основе ролей

    Описание:
        Плагин создан для расширенного разграничения пользователя по правам доступа, и реализует
    систему RBAC.
    Плагин основывается на ядре авторизации по спецификации DEVCS-2102-31244 (https://dev-cs.ru/threads/2102/post-31244)
    и предоставляет базовые методы групповых политик для взаимодействия с привилегиями сервера и плагинов.
    
    Для простого взаимодействия с плагином рекомендуется использовать плагин:
    AuthSystem (https://dev-cs.ru/resources/471/).
    
    ToDo: 
    - Реализовать "активную" группу для пользователя (может использоваться в тегах) 
    
    
============================================================================================*/


#include <amxmodx>
#include <auth_core>
#include <simplerbac/database/mysql>

/*================================= Информация о плагине ===================================*/
#define PLUG_OBJNAME            "Simple Rbac"
#define PLUG_VERSION            "1.0.0"
#define PLUG_CREATOR            "Boec[SpecOPs]"


/*==================================== Блок переменных =====================================*/
new Array: h_groups;    // Кеш групп
new user_cache[33][UserCache];  // Поднаготная пользователя

new fwd_group_register,         // Форвард для регистрации групп
    fwd_group_postinit,         // Форвард для пост-инициализации
    fwd_rbac_check,             // Форвард для перехвата выдачи привилегий
    fwd_rbac_grant,             // Форвард, констатирующий выдачу одной привилегии
    fwd_rbac_complete           // Форвард, констатирующий окончание выдачи привилегий


/*================== Первичная инициализация и завершение работы плагина ===================*/

public plugin_init() 
{
    h_groups = ArrayCreate(GroupStruct);
    
    fwd_group_register = CreateMultiForward("rbac_groups_register", ET_CONTINUE);
    fwd_group_postinit = CreateMultiForward("rbac_groups_postinit", ET_CONTINUE);
    fwd_rbac_check =     CreateMultiForward("rbac_check", ET_CONTINUE, FP_CELL, FP_CELL);
    fwd_rbac_grant =     CreateMultiForward("rbac_on_grant", ET_CONTINUE, FP_CELL, FP_CELL);
    fwd_rbac_complete =  CreateMultiForward("rbac_complete", ET_CONTINUE, FP_CELL);
    
    for(new i=0; i<33; i++) 
        user_cache[i][pc_relation] = _:ArrayCreate();
}


public plugin_natives() 
{
	register_native("rbac_group_add",   "native__group_add");
	register_native("rbac_group_get",   "native__group_get");
	register_native("rbac_group_set",   "native__group_set");
	register_native("rbac_member_of",   "native__member_of");
	register_native("rbac_usermod",     "native__usermod");
	register_native("rbac_deluser",     "native__deluser");
	register_native("rbac_promote",     "native__promote");
	register_native("rbac_demote",      "native__demote");
}


public plugin_cfg()
{
    new group[GroupStruct], res;
    
    // Инициализируем БД
    storage_init();
    
    // С целью удобства в условиях - создаём нулевую группу
    ArrayPushArray(h_groups, group);
    
    // Вызываем форвард для регистрации групп
    ExecuteForward(fwd_group_register, res);
    
    // Объявляем время постинициализации! Viva la revolution! >:D
    ExecuteForward(fwd_group_postinit, res);
    
    for(new i=0; i<33; i++)
        user_cache[i][pc_relation] = ArrayCreate();
}


public plugin_end()
{
    for(new i=0; i<33; i++)
        ArrayDestroy(user_cache[i][pc_relation]);
     
    ArrayDestroy(h_groups);
}


/*========================================= События ========================================*/

public auth_status_change(player_id, new_status, old_status, user_id)
{
    if(new_status == AUTH_SUCCESS) {
        user_read_privileges(player_id, user_id);
    } else {
        user_drop_privileges(player_id);
    }
}


/*============================= Обработчики изменения привилегий ===========================*/
user_read_privileges(player_id, user_id)
{
    // Читаем группы у пользователя и их количество
    storage_find_usergroups(player_id, user_id);
}

user_set_privileges(player_id, Array:groups)
{
    new res, length = ArraySize(groups);
    
    // Инициализиуем события
    for(new i=0, gid; i<length; i++) {
        // Получаем gID группы и спрашиваем другие плагины о валидности действия
        gid = ArrayGetCell(groups, i);
        
        promote_user(player_id, gid);
    }
    
    ExecuteForward(fwd_rbac_complete, res, player_id);
}


user_drop_privileges(player_id)
{
    ArrayClear(user_cache[player_id][pc_relation]);
    user_cache[player_id][pc_user_id] = 0;
    user_cache[player_id][pc_active_group] = 0;
}


/*===================================== Нативы плагина =====================================*/

/**
* Метод регистрирует новую группу/привилегию (см. GroupStruct)
* @Param GroupStruct:api_key; - ключ
* @Param any:value;           - значение
* @OptParam [...];            - последовательность пар ключ-значение
* @return group_id            - уникальный номер группы/привилегии
*
* @usage rbac_group_add(api_key, value[, api_key, value[...]);
* @usage rbac_group_add(GroupStruct, group);
* @usage rbac_group_add(gs_name, "Sudoers", gs_tag, "su");
*/
public native__group_add(pluginID, args)
{
    new group[GroupStruct] = group_proto;           // Запись группы
    
    // Парсим аргументы натива
    parse_native_arguments(args, GroupStruct, group);
    
    // Проверки уникальности группы и запись в кеш
    return create_group_get_id(pluginID, group);
}


/**
* Метод получает группу/привилегию по её id
* @Param GroupStruct:api_key; - ключ
* @Param any:value;           - значение
* @OptParam [...];            - последовательность пар ключ-значение
* @RetParam data[GroupStruct];- массив, в который будут записаны значения
*
* @usage rbac_group_get(api_key, value[, api_key, value[...]);
* @usage rbac_group_get(GroupStruct, group);
* @usage rbac_group_get(gs_name, "Sudoers");
*/
public native__group_get(pluginID, args)
{
    new group[GroupStruct] = group_proto;           // Запись группы
    new tmp[GroupStruct];
    parse_native_arguments(args, GroupStruct, group);
    
    if(strlen(group[gs_name])) {
        for(new tmp[GroupStruct], i=0, len=ArraySize(h_groups); i<len;i++) {
            ArrayGetArray(h_groups, i, tmp);
            if(equali(tmp[gs_name], group[gs_name])) {
                set_array(3, tmp, GroupStruct);
            }
        }
    }
    
    if(group[gs_group_id]) {
        ArrayGetArray(h_groups, group[gs_group_id], tmp);
        set_array(3, tmp, GroupStruct);
    }
}


/**
* Метод изменяе группу/привилегию по её id
* @Param group_id;            - уникальный номер группы/привилегии, которую будем менять
* @Param GroupStruct:api_key; - ключ
* @Param any:value;           - значение
* @OptParam [...];            - последовательность пар ключ-значение
*
* @usage rbac_group_set(group_id, api_key, value[, api_key, value[...]);
* @usage rbac_group_set(1, GroupStruct, group);
* @usage rbac_group_set(1, gs_name, "Sudoers");
*/
public native__group_set(pluginID, args)
{
    new group[GroupStruct] = group_proto;           // Запись группы
    new gid = get_param_byref(1);
    
    // Парсим аргументы натива
    parse_native_arguments(args, GroupStruct, group, 1);
    
    ArraySetArray(h_groups, gid, group);
}


/**
* Метод проверяет принадлежность игрока к группе, или наличие привилегии
* @Param player_id;           - номер игрока на сервере
* @Param group_id;            - уникальный номер группы/привилегии
*
* @usage rbac_mebmer_of(player_id, group_id);
* @usage rbac_mebmer_of(1, 5);
*/
public native__member_of(pluginID, args)
{
    new pid = get_param_byref(1), gid = get_param_byref(2);
    new length = ArraySize(user_cache[pid][pc_relation]);
    for(new i=0; i<length; i++) 
        if(ArrayGetCell(user_cache[i][pc_relation], i) == gid)
            return true;
    
    return false; 
}


/**
* Метод изменяет связку пользователь-группа
* @Param user_id;             - уникальный номер игрока
* @Param group_name;          - название группы
* @Param UserGroupStruct:key; - ключ
* @Param any:value;           - значение
* @OptParam [...];            - последовательность пар ключ-значение
*
* @usage rbac_usermod(user_id, group_name, api_key, value[, api_key, value[...]);
* @usage rbac_usermod(1, "VIP", ugs_expire, %timestamp%);
*/
public native__usermod(pluginID, args)
{
    new relation[UserGroupStruct];
    relation[ugs_user_id] = get_param_byref(1);
    get_string(2, relation[ugs_group_name], charsmax(relation[ugs_group_name]));
    
    parse_native_arguments(args, UserGroupStruct, relation);
    
    storage_replace_usergroup(relation);
}


/**
* Метод удаляет у игрока группу/привилегию по её имени из БД
* @Param player_id;           - номер игрока на сервере
* @Param group_name;          - имя группы
*
* @usage rbac_usermod(player_id, group_name);
* @usage rbac_usermod(1, "VIP");
*/
public native__deluser(pluginID, args)
{
    new relation[UserGroupStruct];
    relation[ugs_user_id] = get_param_byref(1);
    get_string(2, relation[ugs_group_name], charsmax(relation[ugs_group_name]));
    parse_native_arguments(args, UserGroupStruct, relation, 2);
    
    storage_deluser(relation);
}


/**
* Метод даёт игроку группу/привилегию по её id
* @Param player_id;           - номер игрока на сервере
* @Param group_id;            - уникальный номер группы/привилегииие
*
* @usage rbac_usermod(player_id, group_id);
* @usage rbac_usermod(1, 5);
*/
public native__promote(pluginID, args)
{
    new pid = get_param_byref(1);
    new gid = get_param_byref(2);
    
    promote_user(pid, gid);
}


/**
* Метод удаляет у игрока группу/привилегию по её id
* @Param player_id;           - номер игрока на сервере
* @Param group_id;            - уникальный номер группы/привилегииие
*
* @usage rbac_usermod(player_id, group_id);
* @usage rbac_usermod(1, 5);
*/
public native__demote(pluginID, args)
{
    new pid = get_param_byref(1);
    new gid = get_param_byref(2);
    
    for(new i=0, len=ArraySize(user_cache[pid][pc_relation]); i<len;i++) {
        if(gid == ArrayGetCell(user_cache[pid][pc_relation], i)) {
            ArrayDeleteItem(user_cache[pid][pc_relation], i);
            return;
        }
    }
}


/*================================== Прочие методы плагина =================================*/
// Метод добавляет группу/привилегию пользователю без добавления в БД
promote_user(pid, gid)
{
    if(rbac_member_of(pid, gid))
        return;

    new res;
    ExecuteForward(fwd_rbac_check, res, pid, gid);
        
    // Если пользователь может состоять в группе - добавляем привилегии
    if(res) {
        ArrayPushCell(user_cache[pid][pc_relation], gid);
        ExecuteForward(fwd_rbac_grant, res, pid, gid);
        server_print("[S-RBAC] Player set privileges! [%d::%d]", pid, gid);
    }
}

// Найти ID группы по её имени
group_find_byname(name[]) 
{
    new group[GroupStruct];
    for(new i=1, len=ArraySize(h_groups); i<len; i++) {
        ArrayGetArray(h_groups, i, group);
        if(equali(name, group[gs_name])) {
            return i;
        }
    }
    return 0;
}

// Метод проверяет уникальность группы
// Если она не уникальна - предупреждение в логи
create_group_get_id(pluginID, group[GroupStruct])
{
    new plg_name[32], gid;
    
    gid = group_find_byname(group[gs_name])
    
    if(gid) {
        get_plugin(.index = pluginID, .name = plg_name, .len2 = 31);
        log_amx("[S-RBAC] Warning: Group collision! Plugin: %s", plg_name);
        return gid;
    } else {
        group[gs_group_id] = ArraySize(h_groups)-1;
        return ArrayPushArray(h_groups, group)-1;
    }
}

// Метод для парсинга структуры по парам ключ-значение
parse_native_arguments(args, type, data[], param = 0) 
{
    // Т.к. user и thread_info - массивы, а массивы передаются через указатели,
    // и если мы изменим значения здесь, то они изменятся и в месте, откуда вызван парсер
    // Это позволит держать код DRY.
    static property;
    
    do {
        property = get_param_byref(++param);

        // Смотрим тип структуры для разбора параметров
        switch(type) {
            case GroupStruct: {
                switch(property) {
                    case GroupStruct: get_array(++param, data, GroupStruct);
                    case gs_name: get_string(++param, data[gs_name], charsmax(data[gs_name]));
                    case gs_alias: get_string(++param, data[gs_alias], charsmax(data[gs_alias]));
                    case gs_tag: get_string(++param, data[gs_tag], charsmax(data[gs_tag]));
                }
            }
            case UserGroupStruct: {
                switch(property) {
                    case UserGroupStruct: get_array(++param, data, UserGroupStruct);
                    case ugs_group_name: get_string(++param, data[ugs_group_name], charsmax(data[ugs_group_name]));
                    case ugs_user_id,
                         ugs_is_active,
                         ugs_expires: data[property] = get_param_byref(++param);
                }
            }
        }
    } while (param <= args);
    
    return;
}

