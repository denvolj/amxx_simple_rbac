

#if defined _simplerbac_storage_interface_included
        #endinput
#endif
#define _simplerbac_storage_interface_included

#include <simple_rbac>
#include <sqlx> 


/*============================= Конфигурация базы данных ===================================*/
new const db_host[]     = "localhost";
new const db_username[] = "root";
new const db_password[] = "root";
new const db_database[] = "zombielite";
/*==========================================================================================*/


/*=============================== Структуры базы данных ====================================*/
enum _:SQLD
{
	Handle:sqld_tuple,
	Handle:sqld_instance
}; 

/*============================= Блок констант и запросов ===================================*/
const SQL_QLIM = 1024;

new const RBAC_USER_GROUP_CREATE[] = 
    "CREATE TABLE IF NOT EXISTS rbac_user_group\
    ( \
        user_id int unsigned not null, \
        group_name varchar(%d) not null, \
        expires int unsigned default 0, \
        UNIQUE KEY (user_id, group_name) \
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
    
new const RBAC_REPLACE_USER_GROUP[] = "REPLACE INTO rbac_user_group \
    (user_id, group_name, expires) VALUES (%s);";
new const RBAC_SELECT_USER_GROUP[] = "SELECT * FROM rbac_user_group WHERE user_id=%d AND (expires<%d OR expires=0)";
new const RBAC_DELETE_USER_GROUP[] = "DELETE FROM rbac_user_group WHERE user_id=%d AND group_name='%s';";


/*=============================== Реализация взаимодействий ================================*/
storage_init() {
    new query[SQL_QLIM]; query = RBAC_USER_GROUP_CREATE;
    
    format(query, charsmax(query), query, GROUPNAME_MAXLEN);
    mysql_exec(query);
}

storage_find_usergroups(player_id, user_id)
{
    new thread[2];
    new query[SQL_QLIM]; query = RBAC_SELECT_USER_GROUP;
    
    thread[0] = player_id;
    thread[1] = user_id;
    
    format(query, charsmax(query), query, user_id, get_systime());
    
    mysql_exec(query, "thread__find_usergroups", thread, 2);
}


storage_replace_usergroup(relation[UserGroupStruct])
{
    new query[SQL_QLIM]; query = RBAC_REPLACE_USER_GROUP;
    new value[SQL_QLIM];
    
    mysql_escape_string(value, charsmax(value), relation[ugs_group_name]);
    
    format(value, charsmax(value), "%d, '%s', %d", relation[ugs_user_id], value, relation[ugs_expires]);
    
    format(query, charsmax(query), query, value); 
    mysql_exec(query, "mysql_query_handler");
}


storage_deluser(relation[UserGroupStruct])
{
    new query[SQL_QLIM]; query = RBAC_DELETE_USER_GROUP;
    new value[GROUPNAME_MAXLEN*2];
    
    mysql_escape_string(value, charsmax(value), relation[ugs_group_name]);
    
    format(query, charsmax(query), query, relation[ugs_user_id], value); 
    mysql_exec(query, "mysql_query_handler");
}


public thread__find_usergroups(failstate, Handle:query, error[], errnum, data[], size, Float:queuetime)
{
    new temp[UserGroupStruct], group[GroupStruct], Array:groups = ArrayCreate();
    new player_id; player_id = data[0];
    new gid;
    while(SQL_MoreResults(query)) {
        parse_results(query, temp);
        copy(group[gs_name], charsmax(group[gs_name]), temp[ugs_group_name]);
        gid = create_group_get_id(0, group);
        ArrayPushCell(groups, gid);
        SQL_NextRow(query);
    } 
    user_set_privileges(player_id, groups);
}

// Метод, исполняющий запрос (поточный, последовательный - не важно)
stock any:mysql_exec(const sql_query[], callback[] = "mysql_query_handler", thread_info[] = "", len = 0) {
    static database[SQLD];
    database[sqld_tuple] = SQL_MakeDbTuple(db_host, db_username, db_password, db_database);

    // Дебажируем вывод :3
    server_print("[MySQL] Query: %s", sql_query);

    SQL_ThreadQuery(database[sqld_tuple], callback, sql_query, thread_info, len);

    mysql_close(database);

    return true;
}


// Убийца всех хендлеров :3
stock mysql_close(instance[SQLD]) {
    if(instance[sqld_instance] != Empty_Handle)
        SQL_FreeHandle(instance[sqld_instance]);
    if(instance[sqld_tuple] != Empty_Handle)
        SQL_FreeHandle(instance[sqld_tuple]); 
}


// Унифицированный приемщик результатов, если нужно было только выполнить запрос
public mysql_query_handler(failstate, Handle:query, error[], errnum, data[], size, Float:queuetime) {
    if(failstate != TQUERY_SUCCESS)    server_print("[MySQL] SQL error [%d]: %s", errnum, error);
}


// Парсер результатов в структуру
parse_results(Handle:sql_results, data[UserGroupStruct]) {
    new parsed = 0;
    data[ugs_user_id] = SQL_ReadResult(sql_results, parsed++);
    SQL_ReadResult(sql_results, parsed++, data[ugs_group_name], charsmax(data[ugs_group_name]));
    data[ugs_expires] = SQL_ReadResult(sql_results, parsed++);
}


// Избегаем опасных символов в запросах
stock mysql_escape_string(dest[], len, const source[])
{
	copy(dest, len, source);
	
	replace_all(dest,len,"\\","\\\\");
	replace_all(dest,len,"\0","\\0'");
	replace_all(dest,len,"\n","\\n");
	replace_all(dest,len,"\r","\\r");
	replace_all(dest,len,"'","\'");
	replace_all(dest,len,"`","\`");
	replace_all(dest,len,"\x1a","\\x1a");
	replace_all(dest,len,"^"","\^"");
}

