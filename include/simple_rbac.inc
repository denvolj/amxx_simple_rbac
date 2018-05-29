
#if defined _simplerbac_included
        #endinput
#endif
#define _simplerbac_included


/*================================= Константы плагина ======================================*/
#define GROUPNAME_MAXLEN 64
#define GROUPTAG_MAXLEN 16

#define YEAR DAY*365
#define MONTH DAY*30
#define DAY HOUR*24
#define HOUR MINUTE*60
#define MINUTE 60

/*================================= Структуры плагина ======================================*/
// Структура записи группы
// Для справки: пермишны не записываются в БД
enum _:GroupStruct {
    gs_group_id,                    // ID группы
    gs_permission,                  // Является ли пермишном?
    gs_name[GROUPNAME_MAXLEN],      // Название группы
    gs_alias[GROUPNAME_MAXLEN],     // Альтернативное имя (если есть необходимость переименовать группу)
    gs_tag[GROUPTAG_MAXLEN],        // Тег группы
    gs_flags                        // Бит-сумма флагов доступа
}
#define group_proto { 0, "", "", "", "", 0}

// Структура связующей таблицы пользователь-группа
enum _:UserGroupStruct {
    ugs_user_id,                    // Номер пользователя
    ugs_group_name[GROUPNAME_MAXLEN], // Название группы
    ugs_is_active,                  // Является ли эта группа основной для игрока?
    ugs_expires                     // До какого времени выдана группа
}

// Кеш игрока информации пользователя
enum _:UserCache {
    pc_user_id,                     // Номер зарегистрированного пользователя   
    pc_active_group,                // Номер активной группы игрока
    Array:pc_relation               // Массив с группами и привилегиями
}


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
native rbac_group_add(...);


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
native rbac_group_get(...);


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
native rbac_group_set(...);


/**
* Метод проверяет принадлежность игрока к группе, или наличие привилегии
* @Param player_id;           - номер игрока на сервере
* @Param group_id;            - уникальный номер группы/привилегии
*
* @usage rbac_mebmer_of(player_id, group_id);
* @usage rbac_mebmer_of(1, 5);
*/
native rbac_member_of(...);


/**
* Метод удаляет у игрока группу/привилегию по её id
* @Param player_id;           - номер игрока на сервере
* @Param group_id;            - уникальный номер группы/привилегииие
*
* @usage rbac_usermod(player_id, group_id);
* @usage rbac_usermod(1, 5);
*/
native rbac_usermod(...);


/**
* Метод удаляет у игрока группу/привилегию по её имени из БД
* @Param player_id;           - номер игрока на сервере
* @Param group_name;          - имя группы
*
* @usage rbac_deluser(player_id, group_name);
* @usage rbac_deluser(1, "VIP");
*/
native rbac_deluser(...);


/**
* Метод даёт игроку группу/привилегию по её id
* @Param player_id;           - номер игрока на сервере
* @Param group_id;            - уникальный номер группы/привилегииие
*
* @usage rbac_promote(player_id, group_id);
* @usage rbac_promote(1, 5);
*/
native rbac_promote(...);




stock group_equal(const data[GroupStruct], field, comparewith[GroupStruct] = group_proto)
{
        switch(field)
        {
                case gs_name, gs_alias, gs_tag:
                        return (strcmp(data[field], comparewith[field])==0);
                case gs_group_id, group_equal:
                        return (data[field] == comparewith[field]);
                
                default:
                {
                        server_print("[stock SimpleRbac::group_equal] Non-struct offsets used in comparison. Returning false.");
                        return false;
                }
        }
        return false;
}
