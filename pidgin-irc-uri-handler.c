
#define PURPLE_PLUGINS

#include <glib.h>

#include <plugin.h>
#include <account.h>
#include <accountopt.h>
#include <prpl.h>
#include <debug.h>
#include <core.h>

#include <strings.h>

#ifndef _
#	define _(a) a
#endif

PurplePluginProtocolInfo *irc_prpl_info;
static GHashTable *host_aliases = NULL;

static PurpleAccount *
find_irc_account(const gchar *host)
{
	PurpleAccount *acct = NULL;
	gchar *hostsuffix = g_strconcat("@", host, NULL);
	gchar *pos;
	GList *l;
	
	if ((pos = strchr(hostsuffix, ':')))
		*pos = '\0';
	
	
	for(l = purple_accounts_get_all();
		l;
		l = l->next)
	{
		if (g_str_equal("prpl-irc", purple_account_get_protocol_id(l->data))
			&& g_str_has_suffix(purple_account_get_username(l->data), hostsuffix)
			&& purple_account_is_connected(l->data)) {
			acct = l->data;
			break;
		}
	}
	
	g_free(hostsuffix);
	return acct;
}

static gboolean
irc_uri_handler(const char *proto, const char *cmd, GHashTable *params)
{
	PurpleAccount *acct;
	gchar *temp;
	const gchar *pos;
	gchar **split;
	const gchar *host, *target, *port;
	gboolean secure = FALSE;
	gboolean isnick = FALSE, isserver = FALSE, needkey = FALSE, needpass = FALSE;
	gint i;

	//only deal with irc: and ircs: uri's
	if (!g_str_equal(proto, "irc") && !(g_str_equal(proto, "\"irc")))
	{
		if (g_str_equal(proto, "ircs") || g_str_equal(proto, "\"ircs"))
			secure = TRUE;
		else
			return FALSE;
	}
	
	/* irc:[ //[ <host>[:<port>] ]/[<target>] [,needpass] ] */
	
	purple_debug_info("irc-proto-handler", "%s\n", cmd);
	
	while(*cmd && *cmd == '/')
		cmd = cmd + 1;
	
	split = g_strsplit_set(cmd, "/,", -1);
	if (!split) return FALSE;
	
	for(i = g_strv_length(split); i > 2; i--)
	{
		if (g_str_equal(split[i], "isnick"))
			isnick = TRUE;
		else if (g_str_equal(split[i], "isserver"))
			isserver = TRUE;
		else if (g_str_equal(split[i], "needkey"))
			needkey = TRUE;
		else if (g_str_equal(split[i], "needpass"))
			needpass = TRUE;
	}
	
	if (split[0])
	{
		gchar **hostport = g_strsplit(split[0], ":", 2);
		host = hostport[0];
		port = hostport[1];
		acct = find_irc_account(host);
		if (acct == NULL)
		{
			const gchar *pass = g_hash_table_lookup(params, "pass");
			gchar *guest_nick_host;
			
			if (!isserver && !strchr(host, '.'))
			{
				/* TODO: translate network name into a host name */
				host = g_hash_table_lookup(host_aliases, host);
				if (!host) return FALSE;
			}
			
			guest_nick_host = g_strconcat(/* TODO pref: */"Guest", "@", host, NULL); 
			acct = purple_account_new(guest_nick_host, "prpl-irc");
			g_free(guest_nick_host);
			
			if (pass && *pass)
				purple_account_set_password(acct, pass);
			
			purple_account_set_bool(acct, "ssl", secure);
			if (port && *port)
				purple_account_set_int(acct, "port", atoi(port));
			else
				purple_account_set_int(acct, "port", /* TODO pref: */6667);
			
			purple_account_connect(acct);
		}
		g_strfreev(hostport);
		
		if (split[1])
		{
			PurpleConversation *conv = NULL;
			const gchar *msg = g_hash_table_lookup(params, "msg");
			const gchar *key = g_hash_table_lookup(params, "key");
			
			target = purple_url_decode(split[1]);
			if (isnick)
			{
				conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, acct, target);
				purple_conversation_present(conv);
			} else {
				PurpleConnection *pc = purple_account_get_connection(acct);
				GHashTable *chat_params;
				gchar *real_target;
				
				if (target[0] != '#' && target[0] != '&' && target[0] != '+')
					real_target = g_strconcat(/* TODO pref: */"#", target, NULL);
				else
					real_target = g_strdup(target);
				chat_params = irc_prpl_info->chat_info_defaults(pc, real_target);
				
				if (key && *key)
					g_hash_table_insert(chat_params, "password", g_strdup(key));
				
				irc_prpl_info->join_chat(pc, chat_params);
				
				conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, real_target, acct);
				g_free(real_target);
			}
			if (conv != NULL && msg && *msg)
				purple_conv_send_confirm(conv, msg);
		}
	}
	
	g_strfreev(split);
	
	return TRUE;
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
	PurplePlugin *irc_prpl;
	
	irc_prpl = purple_find_prpl("prpl-irc");
	if (irc_prpl == NULL) return FALSE;
	irc_prpl_info = PURPLE_PLUGIN_PROTOCOL_INFO(irc_prpl);
	if (irc_prpl_info == NULL) return FALSE;
	
	purple_signal_connect(purple_get_core(), "uri-handler", plugin, PURPLE_CALLBACK(irc_uri_handler), NULL);
	
	host_aliases = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
	g_hash_table_insert(host_aliases, "efnet", "irc.choopa.net");
	g_hash_table_insert(host_aliases, "moznet", "irc.mozilla.org");
	g_hash_table_insert(host_aliases, "hybridnet", "irc.ssc.net");
	g_hash_table_insert(host_aliases, "slashnet", "irc.slashnet.org");
	g_hash_table_insert(host_aliases, "dalnet", "irc.dal.net");
	g_hash_table_insert(host_aliases, "undernet", "irc.undernet.org");
	g_hash_table_insert(host_aliases, "freenode", "irc.freenode.net");
	g_hash_table_insert(host_aliases, "gamesurge", "irc.gamesurge.net");
	g_hash_table_insert(host_aliases, "quakenet", "irc.quakenet.org");
	g_hash_table_insert(host_aliases, "spidernet", "irc.spidernet.org");
	
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	g_hash_table_destroy(host_aliases);
	
	return TRUE;
}

static void
plugin_init(PurplePlugin *plugin)
{
	PurpleAccountOption *option;
	PurplePluginInfo *info = plugin->info;
	
	info->dependencies = g_list_prepend(info->dependencies, "prpl-irc");
}

static PurplePluginInfo info = 
{
	PURPLE_PLUGIN_MAGIC,
	2,
	2,
	PURPLE_PLUGIN_STANDARD,
	NULL,
	0,
	NULL,
	PURPLE_PRIORITY_LOWEST,

	"eionrobb-irc-uri-handler",
	"IRC URI Protocol Handler",
	"0.2",
	"Handle the irc: uri protocol",
	"Allows you to click on irc: and ircs: URIs",
	"Eion Robb <eionrobb@gmail.com>",
	"https://github.com/EionRobb/pidgin-irc-uri-handler", //URL
	
	plugin_load,
	plugin_unload,
	NULL,
	
	NULL,
	NULL,
	NULL,
	NULL,
	
	NULL,
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(ircformat, plugin_init, info);
