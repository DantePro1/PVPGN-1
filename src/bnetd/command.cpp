#include "common/setup_before.h"
#include "command.h"

#include <cctype>
#include <cerrno>
#include <cstring>
#include <cstdlib>

#include "compat/strcasecmp.h"
#include "compat/snprintf.h"
#include "common/tag.h"
#include "common/util.h"
#include "common/version.h"
#include "common/eventlog.h"
#include "common/bnettime.h"
#include "common/addr.h"
#include "common/packet.h"
#include "common/bnethash.h"
#include "common/list.h"
#include "common/proginfo.h"
#include "common/queue.h"
#include "common/bn_type.h"
#include "common/xalloc.h"
#include "common/xstr.h"
#include "common/trans.h"
#include "common/lstr.h"

#include "connection.h"
#include "message.h"
#include "channel.h"
#include "game.h"
#include "team.h"
#include "account.h"
#include "account_wrap.h"
#include "server.h"
#include "prefs.h"
#include "ladder.h"
#include "timer.h"
#include "helpfile.h"
#include "mail.h"
#include "runprog.h"
#include "alias_command.h"
#include "realm.h"
#include "ipban.h"
#include "command_groups.h"
#include "news.h"
#include "topic.h"
#include "friends.h"
#include "clan.h"
#include "common/setup_after.h"
#include "common/flags.h"

namespace pvpgn
{

	namespace bnetd
	{

		static char const * bnclass_get_str(unsigned int cclass);
		static void do_whisper(t_connection * user_c, char const * dest, char const * text);
		static void do_whois(t_connection * c, char const * dest);
		static void user_timer_cb(t_connection * c, std::time_t now, t_timer_data str);

		char msgtemp[MAX_MESSAGE_LEN];
		char msgtemp2[MAX_MESSAGE_LEN];

		static char const * bnclass_get_str(unsigned int cclass) {
			switch (cclass) {
			case PLAYERINFO_DRTL_CLASS_WARRIOR:
				return "warrior";
			case PLAYERINFO_DRTL_CLASS_ROGUE:
				return "rogue";
			case PLAYERINFO_DRTL_CLASS_SORCERER:
				return "sorcerer";
			default:
				return "unknown";
			}
		}

		static void do_whisper(t_connection * user_c, char const * dest, char const * text) {
			t_connection * dest_c;
			char const *   tname;

			if (account_get_auth_mute(conn_get_account(user_c)) == 1) {
				message_send_text(user_c, message_type_error, user_c, "Your account has been muted, you can't whisper to other users.");
				return;
			}

			if (!(dest_c = connlist_find_connection_by_name(dest, conn_get_realm(user_c)))) {
				message_send_text(user_c, message_type_error, user_c, "That user is not logged on.");
				return;
			}

			if (conn_get_dndstr(dest_c)) {
				snprintf(msgtemp, sizeof(msgtemp), "%.64s is unavailable (%.128s)", conn_get_username(dest_c), conn_get_dndstr(dest_c));
				message_send_text(user_c, message_type_info, user_c, msgtemp);
				return;
			}

			message_send_text(user_c, message_type_whisperack, dest_c, text);

			if (conn_get_awaystr(dest_c)) {
				snprintf(msgtemp, sizeof(msgtemp), "%.64s is away (%.128s)", conn_get_username(dest_c), conn_get_awaystr(dest_c));
				message_send_text(user_c, message_type_info, user_c, msgtemp);
			}

			message_send_text(dest_c, message_type_whisper, user_c, text);

			if ((tname = conn_get_username(user_c))) {
				char username[1 + MAX_USERNAME_LEN];
				if (std::strlen(tname)<MAX_USERNAME_LEN) {
					std::sprintf(username, "*%s", tname);
					conn_set_lastsender(dest_c, username);
				}
			}
		}

		static void do_botchat(t_connection * user_c, char const * dest, char const * text) {
			t_connection * dest_c;
			char const *   tname;

			if (!(dest_c = connlist_find_connection_by_name(dest, conn_get_realm(user_c)))) {
				message_send_text(user_c, message_type_error, user_c, "System down, please wait ...");
				return;
			}

			message_send_text(dest_c, message_type_whisper, user_c, text);

			if ((tname = conn_get_username(user_c))) {
				char username[1 + MAX_USERNAME_LEN];
				if (std::strlen(tname)<MAX_USERNAME_LEN) {
					std::sprintf(username, "*%s", tname);
					conn_set_lastsender(dest_c, username);
				}
			}
		}

		static void do_botchatblue(t_connection * user_c, char const * dest, char const * text) {
			t_connection * dest_c;
			char const *   tname;

			if (!(dest_c = connlist_find_connection_by_name(dest, conn_get_realm(user_c)))) { return; }
			message_send_text(dest_c, message_type_info, user_c, text);

			if ((tname = conn_get_username(user_c))) {
				char username[1 + MAX_USERNAME_LEN];
				if (std::strlen(tname)<MAX_USERNAME_LEN) {
					std::sprintf(username, "*%s", tname);
					conn_set_lastsender(dest_c, username);
				}
			}
		}

		static void do_botchatred(t_connection * user_c, char const * dest, char const * text) {
			t_connection * dest_c;
			char const *   tname;

			if (!(dest_c = connlist_find_connection_by_name(dest, conn_get_realm(user_c)))) { return; }
			message_send_text(dest_c, message_type_error, user_c, text);

			if ((tname = conn_get_username(user_c))) {
				char username[1 + MAX_USERNAME_LEN];
				if (std::strlen(tname)<MAX_USERNAME_LEN) {
					std::sprintf(username, "*%s", tname);
					conn_set_lastsender(dest_c, username);
				}
			}
		}

		static void do_whois(t_connection * c, char const * dest) {
			t_connection *    dest_c;
			char              namepart[136];
			char const *      verb;
			t_game const *    game;
			t_channel const * channel;

			if ((!(dest_c = connlist_find_connection_by_accountname(dest))) && (!(dest_c = connlist_find_connection_by_name(dest, conn_get_realm(c))))) {
				t_account * dest_a;
				t_bnettime btlogin;
				std::time_t ulogin;
				struct std::tm * tmlogin;

				if (!(dest_a = accountlist_find_account(dest))) {
					message_send_text(c, message_type_error, c, "Unknown user.");
					return;
				}

				if (conn_get_class(c) == conn_class_bnet) {
					btlogin = time_to_bnettime((std::time_t)account_get_ll_time(dest_a), 0);
					btlogin = bnettime_add_tzbias(btlogin, conn_get_tzbias(c));
					ulogin = bnettime_to_time(btlogin);
					if (!(tmlogin = std::gmtime(&ulogin)))
						std::strcpy(msgtemp, "User was last seen on ?");
					else
						std::strftime(msgtemp, sizeof(msgtemp), "User was last seen on : %a %b %d %H:%M:%S", tmlogin);
				}
				else std::strcpy(msgtemp, "User is offline");
				message_send_text(c, message_type_info, c, msgtemp);
				return;
			}

			if (c == dest_c) {
				std::strcpy(namepart, "You");
				verb = "are";
			}
			else {
				char const * tname;
				std::sprintf(namepart, "%.64s", (tname = conn_get_chatcharname(dest_c, c)));
				conn_unget_chatcharname(dest_c, tname);
				verb = "is";
			}

			if ((game = conn_get_game(dest_c))) {
				snprintf(msgtemp, sizeof(msgtemp), "%s %s using %s and %s currently in %s game \"%.64s\".",
					namepart,
					verb,
					clienttag_get_title(conn_get_clienttag(dest_c)),
					verb,
					game_get_flag(game) == game_flag_private ? "private" : "",
					game_get_name(game));
			}
			else if ((channel = conn_get_channel(dest_c))) {
				snprintf(msgtemp, sizeof(msgtemp), "%s %s using %s and %s currently in channel \"%.64s\".",
					namepart,
					verb,
					clienttag_get_title(conn_get_clienttag(dest_c)),
					verb,
					channel_get_name(channel));
			}
			else
				snprintf(msgtemp, sizeof(msgtemp), "%s %s using %s.",
				namepart,
				verb,
				clienttag_get_title(conn_get_clienttag(dest_c)));
			message_send_text(c, message_type_info, c, msgtemp);

			if (conn_get_dndstr(dest_c)) {
				snprintf(msgtemp, sizeof(msgtemp), "%s %s refusing messages (%.128s)",
					namepart,
					verb,
					conn_get_dndstr(dest_c));
				message_send_text(c, message_type_info, c, msgtemp);
			}
			else if (conn_get_awaystr(dest_c)) {
				snprintf(msgtemp, sizeof(msgtemp), "%s away (%.128s)",
					namepart,
					conn_get_awaystr(dest_c));
				message_send_text(c, message_type_info, c, msgtemp);
			}
		}

		static void user_timer_cb(t_connection * c, std::time_t now, t_timer_data str) {
			if (!c) {
				eventlog(eventlog_level_error, __FUNCTION__, "got NULL connection");
				return;
			}
			if (!str.p) {
				eventlog(eventlog_level_error, __FUNCTION__, "got NULL str");
				return;
			}
			if (now != (std::time_t)0)
				message_send_text(c, message_type_info, c, (char*)str.p);
			xfree(str.p);
		}

		typedef int(*t_command)(t_connection * c, char const * text);

		typedef struct {
			const char * command_string;
			t_command    command_handler;
		} t_command_table_row;

		static int command_set_flags(t_connection * c);
		static int _handle_games_command(t_connection * c, char const * text);

		static int _handle_finger_command(t_connection * c, char const * text);
		static int _handle_ping_command(t_connection * c, char const * text);


		// New Battlenet
		static int _handle_clan_command(t_connection * c, char const * text);
		static int _handle_admin_command(t_connection * c, char const * text);
		static int _handle_operator_command(t_connection * c, char const * text);
		static int _handle_lockacct_command(t_connection * c, char const * text);
		static int _handle_unlockacct_command(t_connection * c, char const * text);
		static int _handle_muteacct_command(t_connection * c, char const * text);
		static int _handle_unmuteacct_command(t_connection * c, char const * text);
		static int _handle_whois_command(t_connection * c, char const * text);
		static int _handle_voice_command(t_connection * c, char const * text);
		static int _handle_devoice_command(t_connection * c, char const * text);
		static int _handle_watch_command(t_connection * c, char const * text);
		static int _handle_unwatch_command(t_connection * c, char const * text);
		static int _handle_watchall_command(t_connection * c, char const * text);
		static int _handle_unwatchall_command(t_connection * c, char const * text);
		static int _handle_whisper_command(t_connection * c, char const * text);
		static int _handle_botchatblue_command(t_connection * c, char const * text);
		static int _handle_botchatred_command(t_connection * c, char const * text);
		static int _handle_users_command(t_connection * c, char const * text);
		static int _handle_quit_command(t_connection * c, char const * text);
		static int _handle_squelch_command(t_connection * c, char const * text);
		static int _handle_unsquelch_command(t_connection * c, char const * text);
		static int _handle_tmpop_command(t_connection * c, char const * text);
		static int _handle_deop_command(t_connection * c, char const * text);
		static int _handle_join_command(t_connection * c, char const * text);
		static int _handle_rejoin_command(t_connection * c, char const * text);
		static int _handle_announceblue_command(t_connection * c, char const * text);
		static int _handle_announcered_command(t_connection * c, char const * text);
		static int _handle_away_command(t_connection * c, char const * text);
		static int _handle_dnd_command(t_connection * c, char const * text);
		static int _handle_time_command(t_connection * c, char const * text);
		static int _handle_me_command(t_connection * c, char const * text);
		static int _handle_whoami_command(t_connection * c, char const * text);
		static int _handle_flag_command(t_connection * c, char const * text);
		static int _handle_moderate_command(t_connection * c, char const * text);
		static int _handle_commandgroups_command(t_connection * c, char const * text);
		static int _handle_set_command(t_connection * c, char const * text);
		static int _handle_addacct_command(t_connection * c, char const * text);
		static int _handle_chpass_command(t_connection * c, char const * text);
		static int _handle_kick_command(t_connection * c, char const * text);
		static int _handle_reply_command(t_connection * c, char const * text);
		static int _handle_kill_command(t_connection * c, char const * text);
		static int _handle_killsession_command(t_connection * c, char const * text);
		static int _handle_serverban_command(t_connection * c, char const * text);
		static int _handle_channels_command(t_connection * c, char const * text);
		static int _handle_ipscan_command(t_connection * c, char const * text);
		static int _handle_friends_command(t_connection * c, char const * text);
		static int _handle_move_command(t_connection * c, char const * text);
		static int _handle_seticon_command(t_connection * c, char const *text);
		static int _handle_icon_command(t_connection * c, char const *text);

		// NEW BATTLENET BOT
		static int _handle_botevent_command(t_connection * c, char const * text);
		static int _handle_botrules_command(t_connection * c, char const * text);
		static int _handle_botdonate_command(t_connection * c, char const * text);
		static int _handle_botcoin_command(t_connection * c, char const * text);
		static int _handle_botcreate_command(t_connection * c, char const * text);
		static int _handle_botstatus_command(t_connection * c, char const * text);
		static int _handle_botchatstaff_command(t_connection * c, char const * text);
		static int _handle_botaccept_command(t_connection * c, char const * text);
		static int _handle_botdecline_command(t_connection * c, char const * text);
		static int _handle_botrequest_command(t_connection * c, char const * text);
		static int _handle_botstaff_command(t_connection * c, char const * text);
		static int _handle_botonline_command(t_connection * c, char const * text);
		static int _handle_botlock_command(t_connection * c, char const * text);
		static int _handle_botunlock_command(t_connection * c, char const * text);
		static int _handle_botmute_command(t_connection * c, char const * text);
		static int _handle_botunmute_command(t_connection * c, char const * text);
		static int _handle_botannounce_command(t_connection * c, char const * text);
		static int _handle_botcmd_command(t_connection * c, char const * text);
		static int _handle_botadd_command(t_connection * c, char const * text);
		static int _handle_botremove_command(t_connection * c, char const * text);

		static const t_command_table_row standard_command_table[] =
		{
			{ "/games", _handle_games_command },

			{ "/latency", _handle_ping_command },
			{ "/ping", _handle_ping_command },
			{ "/p", _handle_ping_command },

			// New Battlenet
			{ "/help", handle_help_command },
			{ "/?", handle_help_command },
			{ "/ipban", handle_ipban_command },
			{ "/clan", _handle_clan_command },
			{ "/c", _handle_clan_command },
			{ "/admin", _handle_admin_command },
			{ "/operator", _handle_operator_command },
			{ "/lockacct", _handle_lockacct_command },
			{ "/unlockacct", _handle_unlockacct_command },
			{ "/muteacct", _handle_muteacct_command },
			{ "/unmuteacct", _handle_unmuteacct_command },
			{ "/whois", _handle_whois_command },
			{ "/whereis", _handle_whois_command },
			{ "/where", _handle_whois_command },
			{ "/voice", _handle_voice_command },
			{ "/devoice", _handle_devoice_command },
			{ "/watch", _handle_watch_command },
			{ "/unwatch", _handle_unwatch_command },
			{ "/watchall", _handle_watchall_command },
			{ "/unwatchall", _handle_unwatchall_command },
			{ "/msg", _handle_whisper_command },
			{ "/whisper", _handle_whisper_command },
			{ "/w", _handle_whisper_command },
			{ "/m", _handle_whisper_command },
			{ "/botchatblue", _handle_botchatblue_command },
			{ "/botchatred", _handle_botchatred_command },
			{ "/users", _handle_users_command },
			{ "/logout", _handle_quit_command },
			{ "/quit", _handle_quit_command },
			{ "/exit", _handle_quit_command },
			{ "/ignore", _handle_squelch_command },
			{ "/squelch", _handle_squelch_command },
			{ "/unignore", _handle_unsquelch_command },
			{ "/unsquelch", _handle_unsquelch_command },
			{ "/tmpop", _handle_tmpop_command },
			{ "/deop", _handle_deop_command },
			{ "/j", _handle_join_command },
			{ "/join", _handle_join_command },
			{ "/rejoin", _handle_rejoin_command },
			{ "/announceblue", _handle_announceblue_command },
			{ "/announcered", _handle_announcered_command },
			{ "/away", _handle_away_command },
			{ "/dnd", _handle_dnd_command },
			{ "/time", _handle_time_command },
			{ "/me", _handle_me_command },
			{ "/whoami", _handle_whoami_command },
			{ "/flag", _handle_flag_command },
			{ "/moderate", _handle_moderate_command },
			{ "/commandgroups", _handle_commandgroups_command },
			{ "/cg", _handle_commandgroups_command },
			{ "/set", _handle_set_command },
			{ "/addacct", _handle_addacct_command },
			{ "/chpass", _handle_chpass_command },
			{ "/kick", _handle_kick_command },
			{ "/r", _handle_reply_command },
			{ "/reply", _handle_reply_command },
			{ "/kill", _handle_kill_command },
			{ "/killsession", _handle_killsession_command },
			{ "/serverban", _handle_serverban_command },
			{ "/channels", _handle_channels_command },
			{ "/chs", _handle_channels_command },
			{ "/ipscan", _handle_ipscan_command },
			{ "/f", _handle_friends_command },
			{ "/friends", _handle_friends_command },
			{ "/finger", _handle_finger_command },
			{ "/move", _handle_move_command },
			{ "/seticon", _handle_seticon_command },
			{ "/icon", _handle_icon_command },

			// NEW BATTLENET BOT
			{ "/event", _handle_botevent_command },
			{ "/rules", _handle_botrules_command },
			{ "/donate", _handle_botdonate_command },
			{ "/coin", _handle_botcoin_command },
			{ "/create", _handle_botcreate_command },
			{ "/status", _handle_botstatus_command },
			{ "/chat", _handle_botchatstaff_command },
			{ "/accept", _handle_botaccept_command },
			{ "/decline", _handle_botdecline_command },
			{ "/request", _handle_botrequest_command },
			{ "/staff", _handle_botstaff_command },
			{ "/online", _handle_botonline_command },
			{ "/lock", _handle_botlock_command },
			{ "/unlock", _handle_botunlock_command },
			{ "/mute", _handle_botmute_command },
			{ "/unmute", _handle_botunmute_command },
			{ "/announce", _handle_botannounce_command },
			{ "/cmd", _handle_botcmd_command },
			{ "/add", _handle_botadd_command },
			{ "/remove", _handle_botremove_command },

			{ NULL, NULL }

		};

		char const * skip_command(char const * org_text)
		{
			unsigned int i;
			char * text = (char *)org_text;
			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++); /* skip command */
			if (text[i] != '\0') text[i++] = '\0';             /* \0-terminate command */
			for (; text[i] == ' '; i++);
			return &text[i];
		}

		extern int handle_command(t_connection * c, char const * text)
		{
			t_command_table_row const *p;

			for (p = standard_command_table; p->command_string != NULL; p++)
			{
				if (strstart(text, p->command_string) == 0)
				{
					if (!(command_get_group(p->command_string)))
					{
						message_send_text(c, message_type_error, c, "This command has been deactivated");
						return 0;
					}
					if (!((command_get_group(p->command_string) & account_get_command_groups(conn_get_account(c)))))
					{
						message_send_text(c, message_type_error, c, "This command is reserved for admins.");
						return 0;
					}
					if (p->command_handler != NULL) return ((p->command_handler)(c, text));
				}
			}


			if (prefs_get_extra_commands() == 0)
			{
				message_send_text(c, message_type_error, c, "Unknown command.");
				eventlog(eventlog_level_debug, __FUNCTION__, "got unknown standard command \"%s\"", text);
				return 0;
			}

			if (std::strlen(text) >= 2 && std::strncmp(text, "//", 2) == 0)
			{
				handle_alias_command(c, text);
				return 0;
			}

			message_send_text(c, message_type_error, c, "Unknown command.");
			eventlog(eventlog_level_debug, __FUNCTION__, "got unknown command \"%s\"", text);
			return 0;
		}

		// +++++++++++++++++++++++++++++++++ command implementations +++++++++++++++++++++++++++++++++++++++

		struct glist_cb_struct {
			t_game_difficulty diff;
			t_clienttag tag;
			t_connection *c;
		};

		static int _glist_cb(t_game *game, void *data)
		{
			struct glist_cb_struct *cbdata = (struct glist_cb_struct*)data;

			if ((!cbdata->tag || !prefs_get_hide_pass_games() || game_get_flag(game) != game_flag_private) &&
				(!cbdata->tag || game_get_clienttag(game) == cbdata->tag) &&
				(cbdata->diff == game_difficulty_none || game_get_difficulty(game) == cbdata->diff))
			{
				snprintf(msgtemp, sizeof(msgtemp), "%s %u %s",
					game_status_get_str(game_get_status(game)),
					game_get_ref(game),
					game_get_name(game));
				message_send_text(cbdata->c, message_type_info, cbdata->c, msgtemp);
			}

			return 0;
		}

		static int _handle_games_command(t_connection * c, char const *text) {
			unsigned int   i;
			unsigned int   j;
			char           clienttag_str[5];
			char           dest[5];
			struct glist_cb_struct cbdata;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++)
			if (j<sizeof(dest)-1) dest[j++] = text[i];
			dest[j] = '\0';
			for (; text[i] == ' '; i++);

			cbdata.c = c;

			if (std::strcmp(&text[i], "norm") == 0)
				cbdata.diff = game_difficulty_normal;
			else if (std::strcmp(&text[i], "night") == 0)
				cbdata.diff = game_difficulty_nightmare;
			else if (std::strcmp(&text[i], "hell") == 0)
				cbdata.diff = game_difficulty_hell;
			else
				cbdata.diff = game_difficulty_none;

			if (dest[0] == '\0') {
				cbdata.tag = 0;
				message_send_text(c, message_type_info, c, "Currently accessable games:");
			}
			else if (strcasecmp(&dest[0], "all") == 0) {
				cbdata.tag = 0;
				message_send_text(c, message_type_info, c, "All current games:");
			}
			else {
				cbdata.tag = 0;
				if (!tag_check_client(cbdata.tag)) {
					message_send_text(c, message_type_error, c, "No valid clienttag specified.");
					return -1;
				}
				if (cbdata.diff == game_difficulty_none)
					snprintf(msgtemp, sizeof(msgtemp), "Current games of type %.64s", tag_uint_to_str(clienttag_str, cbdata.tag));
				else
					snprintf(msgtemp, sizeof(msgtemp), "Current games of type %.64s %.128s", tag_uint_to_str(clienttag_str, cbdata.tag), &text[i]);
				message_send_text(c, message_type_info, c, msgtemp);
			}

			message_send_text(c, message_type_error, c, "-- GAMES -----");
			gamelist_traverse(_glist_cb, &cbdata);
			return 0;
		}

		static int _handle_ping_command(t_connection * c, char const *text)
		{
			unsigned int i;
			t_connection *	user;
			t_game 	*	game;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++); /* skip command */
			for (; text[i] == ' '; i++);

			if (text[i] == '\0')
			{
				if ((game = conn_get_game(c)))
				{
					for (i = 0; i<game_get_count(game); i++)
					{
						if ((user = game_get_player_conn(game, i)))
						{
							snprintf(msgtemp, sizeof(msgtemp), "%.64s latency: %9u", conn_get_username(user), conn_get_latency(user));
							message_send_text(c, message_type_info, c, msgtemp);
						}
					}
					return 0;
				}
				snprintf(msgtemp, sizeof(msgtemp), "Your latency %9u", conn_get_latency(c));
			}
			else if ((user = connlist_find_connection_by_accountname(&text[i])))
				snprintf(msgtemp, sizeof(msgtemp), "%.64s latency %9u", &text[i], conn_get_latency(user));
			else
				snprintf(msgtemp, sizeof(msgtemp), "Invalid user");

			message_send_text(c, message_type_info, c, msgtemp);
			return 0;
		}

		// New Battlenet
		static int command_set_flags(t_connection * c)
		{
			return channel_set_userflags(c);
		}

		static int _handle_clan_command(t_connection * c, char const * text) {
			t_account * acc;
			t_clanmember * member;
			t_clan * clan;

			if (!(acc = conn_get_account(c))){
				ERROR0("got NULL account");
			}

			text = skip_command(text);
			if ((member = account_get_clanmember_forced(acc)) && (clan = clanmember_get_clan(member)) && (clanmember_get_fullmember(member) == 1)) {
				if (text[0] == '\0') {
					message_send_text(c, message_type_info, c, "--------------------------------------------------------");
					message_send_text(c, message_type_error, c, "Usage: /clan msg [message] (alias: m w whisper)");
					message_send_text(c, message_type_info, c, "** For whispers a message to all your fellow clan members.");
					message_send_text(c, message_type_error, c, "Usage: /clan list (alias: l)");
					message_send_text(c, message_type_info, c, "** For displays your clan members.");
					if (clanmember_get_status(member) >= CLAN_SHAMAN) {
						message_send_text(c, message_type_error, c, "Usage: /clan invite [username] (alias: inv)");
						message_send_text(c, message_type_info, c, "** For invite player to your clan.");
						message_send_text(c, message_type_error, c, "Usage: /clan kick [username] (alias: k)");
						message_send_text(c, message_type_info, c, "** For kick member from your clan.");
						message_send_text(c, message_type_error, c, "Usage: /clan motd [message] (no have alias)");
						message_send_text(c, message_type_info, c, "** For update the clan message of the day to message.");
						message_send_text(c, message_type_error, c, "Usage: /clan [status] [username] (no have alias)");
						message_send_text(c, message_type_info, c, "** For change status member.");
						message_send_text(c, message_type_info, c, "** Status: Chieftain, Shaman, Grunt and Peon.");
					}
					if (clanmember_get_status(member) == CLAN_CHIEFTAIN) {
						message_send_text(c, message_type_info, c, "** Warning! You'll have multi chieftain on clan!");
						message_send_text(c, message_type_error, c, "Usage: /clan [channel] (no have alias)");
						message_send_text(c, message_type_info, c, "** For change clan channel.");
						message_send_text(c, message_type_error, c, "Usage: /clan disband (no have alias)");
						message_send_text(c, message_type_info, c, "** For disband your clan.");
					}
					message_send_text(c, message_type_info, c, "--------------------------------------------------------");
					message_send_text(c, message_type_info, c, "Use: /clan out (alias: o) - for out from clan.");
					return 0;
				}
				if (strstart(text, "msg") == 0 || strstart(text, "m") == 0 || strstart(text, "w") == 0 || strstart(text, "whisper") == 0) {
					char const *msg = skip_command(text);
					if (msg[0] == '\0') {
						message_send_text(c, message_type_info, c, "--------------------------------------------------------");
						message_send_text(c, message_type_error, c, "Usage: /clan msg [message] (alias: m w whisper)");
						message_send_text(c, message_type_info, c, "** For whispers a message to all your fellow clan members.");
					}
					else {
						if (clan_send_message_to_online_members(clan, message_type_null, c, msg) >= 1)
							message_send_text(c, message_type_null, c, msg);
						else
							message_send_text(c, message_type_info, c, "All fellow members of your clan are currently offline.");
					}
				}
				if (strstart(text, "list") == 0 || strstart(text, "l") == 0) {
					char const * friend_;
					char status[128];
					char software[64];
					char msgtemp[MAX_MESSAGE_LEN];
					t_connection * dest_c;
					t_account * friend_acc;
					t_game const * game;
					t_channel const * channel;
					t_friend * fr;
					t_list  * flist;
					int num;
					unsigned int uid;
					t_elem  * curr;
					int i = -1;

					message_send_text(c, message_type_error, c, "-- CLAN MEMBERS -----");
					LIST_TRAVERSE(clan_get_members(clan), curr) {
						i++;
						if (!(member = (t_clanmember*)elem_get_data(curr))) {
							eventlog(eventlog_level_error, __FUNCTION__, "found NULL entry in list");
							continue;
						}
						if (!(friend_acc = clanmember_get_account(member))) {
							eventlog(eventlog_level_error, __FUNCTION__, "member has NULL account");
							continue;
						}

						if (clanmember_get_fullmember(member) == 0)
							continue;

						if (clanmember_get_account(member) && clanmember_get_status(member) == CLAN_CHIEFTAIN) {
							software[0] = '\0';
							if (!(dest_c = connlist_find_connection_by_account(friend_acc)))
								sprintf(status, ", offline");
							else {
								sprintf(software, " using %s", clienttag_get_title(conn_get_clienttag(dest_c)));
								if ((game = conn_get_game(dest_c)))
									sprintf(status, ", in game \"%.64s\"", game_get_name(game));
								else if ((channel = conn_get_channel(dest_c))) {
									if (strcasecmp(channel_get_name(channel), "Arranged Teams") == 0)
										sprintf(status, ", in game AT Preparation");
									else
										sprintf(status, ", in channel \"%.64s\"", channel_get_name(channel));
								}
								else
									sprintf(status, ", is in AT Preparation");
							}

							friend_ = account_get_name(friend_acc);
							if (software[0]) sprintf(msgtemp, "%d: %.16s%.128s, %.64s", i + 1, friend_, status, software);
							else sprintf(msgtemp, "%d: %.16s%.128s", i + 1, friend_, status);
							message_send_text(c, message_type_info, c, msgtemp);
						}

						if (clanmember_get_account(member) && clanmember_get_status(member) == CLAN_SHAMAN) {
							software[0] = '\0';
							if (!(dest_c = connlist_find_connection_by_account(friend_acc)))
								sprintf(status, ", offline");
							else {
								sprintf(software, " using %s", clienttag_get_title(conn_get_clienttag(dest_c)));
								if ((game = conn_get_game(dest_c)))
									sprintf(status, ", in game \"%.64s\"", game_get_name(game));
								else if ((channel = conn_get_channel(dest_c))) {
									if (strcasecmp(channel_get_name(channel), "Arranged Teams") == 0)
										sprintf(status, ", in game AT Preparation");
									else
										sprintf(status, ", in channel \"%.64s\"", channel_get_name(channel));
								}
								else
									sprintf(status, ", is in AT Preparation");
							}

							friend_ = account_get_name(friend_acc);
							if (software[0]) sprintf(msgtemp, "%d: %.16s%.128s, %.64s", i + 1, friend_, status, software);
							else sprintf(msgtemp, "%d: %.16s%.128s", i + 1, friend_, status);
							message_send_text(c, message_type_info, c, msgtemp);
						}

						if (clanmember_get_account(member) && clanmember_get_status(member) == CLAN_GRUNT) {
							software[0] = '\0';
							if (!(dest_c = connlist_find_connection_by_account(friend_acc)))
								sprintf(status, ", offline");
							else {
								sprintf(software, " using %s", clienttag_get_title(conn_get_clienttag(dest_c)));
								if ((game = conn_get_game(dest_c)))
									sprintf(status, ", in game \"%.64s\"", game_get_name(game));
								else if ((channel = conn_get_channel(dest_c))) {
									if (strcasecmp(channel_get_name(channel), "Arranged Teams") == 0)
										sprintf(status, ", in game AT Preparation");
									else
										sprintf(status, ", in channel \"%.64s\"", channel_get_name(channel));
								}
								else
									sprintf(status, ", is in AT Preparation");
							}

							friend_ = account_get_name(friend_acc);
							if (software[0]) sprintf(msgtemp, "%d: %.16s%.128s, %.64s", i + 1, friend_, status, software);
							else sprintf(msgtemp, "%d: %.16s%.128s", i + 1, friend_, status);
							message_send_text(c, message_type_info, c, msgtemp);
						}

						if (clanmember_get_account(member) && clanmember_get_status(member) == CLAN_PEON) {
							software[0] = '\0';
							if (!(dest_c = connlist_find_connection_by_account(friend_acc)))
								sprintf(status, ", offline");
							else {
								sprintf(software, " using %s", clienttag_get_title(conn_get_clienttag(dest_c)));
								if ((game = conn_get_game(dest_c)))
									sprintf(status, ", in game \"%.64s\"", game_get_name(game));
								else if ((channel = conn_get_channel(dest_c))) {
									if (strcasecmp(channel_get_name(channel), "Arranged Teams") == 0)
										sprintf(status, ", in game AT Preparation");
									else
										sprintf(status, ", in channel \"%.64s\"", channel_get_name(channel));
								}
								else
									sprintf(status, ", is in AT Preparation");
							}

							friend_ = account_get_name(friend_acc);
							if (software[0]) sprintf(msgtemp, "%d: %.16s%.128s, %.64s", i + 1, friend_, status, software);
							else sprintf(msgtemp, "%d: %.16s%.128s", i + 1, friend_, status);
							message_send_text(c, message_type_info, c, msgtemp);
						}
					}
					message_send_text(c, message_type_info, c, "--------------------------------------------------------");
					return 0;
				}
				if (strstart(text, "out") == 0 || strstart(text, "o") == 0) {
					t_connection     * dest_c;
					t_account        * friend_acc;
					t_game * game;
					t_channel * channel;
					char stat;
					t_clanmember *member;

					text = skip_command(text);
					if (text[0] == '\0') {
						message_send_text(c, message_type_info, c, "This is one-way action! If you really want");
						message_send_text(c, message_type_info, c, "to leave from clan, type /clan out yes");
						return 0;
					}

					else if (strstart(text, "yes") == 0) {
						if (account_get_clanmember(acc)) {
							clan_remove_member(clan, account_get_clanmember(acc));
							message_send_text(c, message_type_info, c, "You are now out from clan :(");
						}
					}
				}
				if (clanmember_get_status(member) == CLAN_SHAMAN) {
					if (strstart(text, "motd") == 0) {
						const char * msg = skip_command(text);
						if (msg[0] == '\0') {
							message_send_text(c, message_type_info, c, "--------------------------------------------------------");
							message_send_text(c, message_type_error, c, "Usage: /clan motd [message] (no have alias)");
							message_send_text(c, message_type_info, c, "** For whispers a message to all your fellow clan members.");
						}
						else {
							clan_set_motd(clan, msg);
							message_send_text(c, message_type_info, c, "Clan message of day is updated!");
						}
					}
					else if (strstart(text, "invite") == 0 || strstart(text, "inv") == 0) {
						const char * username = skip_command(text);
						t_account * dest_account;
						t_connection * dest_conn;

						if (username[0] == '\0') {
							message_send_text(c, message_type_info, c, "--------------------------------------------------------");
							message_send_text(c, message_type_error, c, "Usage: /clan invite [username] (alias: inv)");
							message_send_text(c, message_type_info, c, "** For invite player to your clan.");
						}
						else {
							if ((dest_account = accountlist_find_account(username)) && (dest_conn = account_get_conn(dest_account)) && (account_get_clan(dest_account) == NULL) && (account_get_creating_clan(dest_account) == NULL)) {
								if (prefs_get_clan_newer_time() > 0)
									clan_add_member(clan, dest_account, CLAN_NEW);
								else
									clan_add_member(clan, dest_account, CLAN_PEON);
								snprintf(msgtemp, sizeof(msgtemp), "User %s was invited to your clan!", username);
								message_send_text(c, message_type_error, c, msgtemp);
								snprintf(msgtemp, sizeof(msgtemp), "You are invited to %s by %s!", clan_get_name(clan), conn_get_chatname(c));
								message_send_text(dest_conn, message_type_error, c, msgtemp);
								snprintf(msgtemp, sizeof(msgtemp), "%s", account_get_channel(acc));
								account_set_channel(dest_account, msgtemp);
							}
							else {
								snprintf(msgtemp, sizeof(msgtemp), "User %s is not online or is already member of clan!", username);
								message_send_text(c, message_type_error, c, msgtemp);
							}
						}
					}
					else if (strstart(text, "kick") == 0 || strstart(text, "k") == 0) {
						t_connection     * dest_c;
						t_account        * friend_acc;
						t_game * game;
						t_channel * channel;
						char stat;
						t_clanmember *member;

						text = skip_command(text);
						if (text[0] == '\0') {
							message_send_text(c, message_type_info, c, "--------------------------------------------------------");
							message_send_text(c, message_type_error, c, "Usage: /clan kick [username] (alias: k)");
							message_send_text(c, message_type_info, c, "** For kick member from your clan.");
							return 0;
						}

						if (!(friend_acc = accountlist_find_account(text))) { message_send_text(c, message_type_info, c, "That user does not exist."); return 0; }
						if (acc == friend_acc) { message_send_text(c, message_type_error, c, "You can't choose yourself!"); return 0; }
						if (clan_get_clanid(account_get_clan(friend_acc)) != clan_get_clanid(clan)) { sprintf(msgtemp, "%s is not members!", text); message_send_text(c, message_type_error, c, msgtemp); return 0; }

						if (member = account_get_clanmember(friend_acc)) {
							char	 status;
							if (status = clanmember_get_status(member)) {
								switch (status) {
								case CLAN_CHIEFTAIN: std::strcat(msgtemp, "Chieftain"); break;
								case CLAN_SHAMAN: std::strcat(msgtemp, "Shaman"); break;
								case CLAN_GRUNT: std::strcat(msgtemp, "Grunt"); break;
								case CLAN_PEON: std::strcat(msgtemp, "Peon"); break;
								default:;
								}
							}
							if (status == CLAN_CHIEFTAIN) {
								sprintf(msgtemp, "You can't kick chieftain!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
							if (status == CLAN_SHAMAN) {
								sprintf(msgtemp, "You can't kick shaman!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
						}

						if (!clan_remove_member(clan, account_get_clanmember(friend_acc))) {
							sprintf(msgtemp, "Successfully kick user %s from clan.", text);
							message_send_text(c, message_type_info, c, msgtemp);
							return 0;
						}
					}
					else if (strstart(text, "grunt") == 0) {
						t_connection * dest_c;
						t_account * friend_acc;
						t_server_friendslistreply_status status;
						t_clanmember *member;

						text = skip_command(text);

						if (text[0] == '\0') {
							message_send_text(c, message_type_info, c, "--------------------------------------------------------");
							message_send_text(c, message_type_error, c, "Usage: /clan grunt [username] (no have alias)");
							message_send_text(c, message_type_info, c, "** For change status member to grunt.");
							return 0;
						}

						if (!(friend_acc = accountlist_find_account(text))) { message_send_text(c, message_type_info, c, "That user does not exist."); return 0; }
						if (acc == friend_acc) { message_send_text(c, message_type_error, c, "You can't choose yourself!"); return 0; }
						if (clan_get_clanid(account_get_clan(friend_acc)) != clan_get_clanid(clan)) { sprintf(msgtemp, "%s is not members!", text); message_send_text(c, message_type_error, c, msgtemp); return 0; }

						if (member = account_get_clanmember(friend_acc)) {
							char	 status;
							if (status = clanmember_get_status(member)) {
								switch (status) {
								case CLAN_CHIEFTAIN: std::strcat(msgtemp, "Chieftain"); break;
								case CLAN_SHAMAN: std::strcat(msgtemp, "Shaman"); break;
								case CLAN_GRUNT: std::strcat(msgtemp, "Grunt"); break;
								case CLAN_PEON: std::strcat(msgtemp, "Peon"); break;
								default:;
								}
							}
							if (status == CLAN_CHIEFTAIN) {
								sprintf(msgtemp, "%s has already on chieftain! You can't change chieftain to grunt!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
							if (status == CLAN_SHAMAN) {
								sprintf(msgtemp, "%s has already on shaman! You can't change shaman to grunt!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
							if (status == CLAN_GRUNT) {
								sprintf(msgtemp, "%s has already on grunt!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
						}

						clanmember_set_status(account_get_clanmember(friend_acc), CLAN_GRUNT);
						sprintf(msgtemp, "Successfully change status grunt for user %s.", text);
						message_send_text(c, message_type_info, c, msgtemp);
					}
					else if (strstart(text, "peon") == 0) {
						t_connection * dest_c;
						t_account * friend_acc;
						t_server_friendslistreply_status status;
						t_clanmember *member;

						text = skip_command(text);

						if (text[0] == '\0') {
							message_send_text(c, message_type_info, c, "--------------------------------------------------------");
							message_send_text(c, message_type_error, c, "Usage: /clan peon [username] (no have alias)");
							message_send_text(c, message_type_info, c, "** For change status member to peon.");
							return 0;
						}

						if (!(friend_acc = accountlist_find_account(text))) { message_send_text(c, message_type_info, c, "That user does not exist."); return 0; }
						if (acc == friend_acc) { message_send_text(c, message_type_error, c, "You can't choose yourself!"); return 0; }
						if (clan_get_clanid(account_get_clan(friend_acc)) != clan_get_clanid(clan)) { sprintf(msgtemp, "%s is not members!", text); message_send_text(c, message_type_error, c, msgtemp); return 0; }

						if (member = account_get_clanmember(friend_acc)) {
							char	 status;
							if (status = clanmember_get_status(member)) {
								switch (status) {
								case CLAN_CHIEFTAIN: std::strcat(msgtemp, "Chieftain"); break;
								case CLAN_SHAMAN: std::strcat(msgtemp, "Shaman"); break;
								case CLAN_GRUNT: std::strcat(msgtemp, "Grunt"); break;
								case CLAN_PEON: std::strcat(msgtemp, "Peon"); break;
								default:;
								}
							}
							if (status == CLAN_CHIEFTAIN) {
								sprintf(msgtemp, "%s has already on chieftain! You can't change chieftain to peon!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
							if (status == CLAN_SHAMAN) {
								sprintf(msgtemp, "%s has already on shaman! You can't change shaman to peon!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
							if (status == CLAN_PEON) {
								sprintf(msgtemp, "%s has already on peon!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
						}

						clanmember_set_status(account_get_clanmember(friend_acc), CLAN_PEON);
						sprintf(msgtemp, "Successfully change status peon for user %s.", text);
						message_send_text(c, message_type_info, c, msgtemp);
					}
				}
				if (clanmember_get_status(member) == CLAN_CHIEFTAIN) {
					if (strstart(text, "motd") == 0) {
						const char * msg = skip_command(text);
						if (msg[0] == '\0') {
							message_send_text(c, message_type_info, c, "--------------------------------------------------------");
							message_send_text(c, message_type_error, c, "Usage: /clan motd [message] (no have alias)");
							message_send_text(c, message_type_info, c, "** For whispers a message to all your fellow clan members.");
						}
						else {
							clan_set_motd(clan, msg);
							message_send_text(c, message_type_info, c, "Clan message of day is updated!");
						}
					}
					else if (strstart(text, "invite") == 0 || strstart(text, "inv") == 0) {
						const char * username = skip_command(text);
						t_account * dest_account;
						t_connection * dest_conn;

						if (username[0] == '\0') {
							message_send_text(c, message_type_info, c, "--------------------------------------------------------");
							message_send_text(c, message_type_error, c, "Usage: /clan invite [username] (alias: inv)");
							message_send_text(c, message_type_info, c, "** For invite player to your clan.");
						}
						else {
							if ((dest_account = accountlist_find_account(username)) && (dest_conn = account_get_conn(dest_account)) && (account_get_clan(dest_account) == NULL) && (account_get_creating_clan(dest_account) == NULL)) {
								if (prefs_get_clan_newer_time() > 0)
									clan_add_member(clan, dest_account, CLAN_NEW);
								else
									clan_add_member(clan, dest_account, CLAN_PEON);
								snprintf(msgtemp, sizeof(msgtemp), "User %s was invited to your clan!", username);
								message_send_text(c, message_type_error, c, msgtemp);
								snprintf(msgtemp, sizeof(msgtemp), "You are invited to %s by %s!", clan_get_name(clan), conn_get_chatname(c));
								message_send_text(dest_conn, message_type_error, c, msgtemp);
								snprintf(msgtemp, sizeof(msgtemp), "%s", account_get_channel(acc));
								account_set_channel(dest_account, msgtemp);
							}
							else {
								snprintf(msgtemp, sizeof(msgtemp), "User %s is not online or is already member of clan!", username);
								message_send_text(c, message_type_error, c, msgtemp);
							}
						}
					}
					else if (strstart(text, "kick") == 0 || strstart(text, "k") == 0) {
						t_connection     * dest_c;
						t_account        * friend_acc;
						t_game * game;
						t_channel * channel;
						char stat;
						t_clanmember *member;

						text = skip_command(text);
						if (text[0] == '\0') {
							message_send_text(c, message_type_info, c, "--------------------------------------------------------");
							message_send_text(c, message_type_error, c, "Usage: /clan kick [username] (alias: k)");
							message_send_text(c, message_type_info, c, "** For kick member from your clan.");
							return 0;
						}

						if (!(friend_acc = accountlist_find_account(text))) { message_send_text(c, message_type_info, c, "That user does not exist."); return 0; }
						if (acc == friend_acc) { message_send_text(c, message_type_error, c, "You can't choose yourself!"); return 0; }
						if (clan_get_clanid(account_get_clan(friend_acc)) != clan_get_clanid(clan)) { sprintf(msgtemp, "%s is not members!", text); message_send_text(c, message_type_error, c, msgtemp); return 0; }

						if (member = account_get_clanmember(friend_acc)) {
							char	 status;
							if (status = clanmember_get_status(member)) {
								switch (status) {
								case CLAN_CHIEFTAIN: std::strcat(msgtemp, "Chieftain"); break;
								case CLAN_SHAMAN: std::strcat(msgtemp, "Shaman"); break;
								case CLAN_GRUNT: std::strcat(msgtemp, "Grunt"); break;
								case CLAN_PEON: std::strcat(msgtemp, "Peon"); break;
								default:;
								}
							}
							if (status == CLAN_CHIEFTAIN) {
								sprintf(msgtemp, "You can't kick chieftain!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
							if (status == CLAN_SHAMAN) {
								sprintf(msgtemp, "You can't kick shaman!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
						}

						if (!clan_remove_member(clan, account_get_clanmember(friend_acc))) {
							sprintf(msgtemp, "Successfully kick user %s from clan.", text);
							message_send_text(c, message_type_info, c, msgtemp);
							return 0;
						}
					}
					else if (strstart(text, "chieftain") == 0) {
						t_connection * dest_c;
						t_account * friend_acc;
						t_server_friendslistreply_status status;
						t_clanmember *member;

						text = skip_command(text);

						if (text[0] == '\0') {
							message_send_text(c, message_type_info, c, "--------------------------------------------------------");
							message_send_text(c, message_type_error, c, "Usage: /clan chieftain [username] (no have alias)");
							message_send_text(c, message_type_info, c, "** For change status member to chieftain.");
							message_send_text(c, message_type_info, c, "** Warning! You'll have multi chieftain on clan!");
							return 0;
						}

						if (!(friend_acc = accountlist_find_account(text))) { message_send_text(c, message_type_info, c, "That user does not exist."); return 0; }
						if (acc == friend_acc) { message_send_text(c, message_type_error, c, "You can't choose yourself!"); return 0; }
						if (!account_get_clan(friend_acc)) { sprintf(msgtemp, "%s is not members!", text); message_send_text(c, message_type_info, c, msgtemp); return 0; }
						if (clan_get_clantag(account_get_clan(friend_acc)) != clan_get_clantag(clan)) { sprintf(msgtemp, "%s is not members!", text); message_send_text(c, message_type_info, c, msgtemp); return 0; }

						if (member = account_get_clanmember(friend_acc)) {
							char	 status;
							if (status = clanmember_get_status(member)) {
								switch (status) {
								case CLAN_CHIEFTAIN: std::strcat(msgtemp, "Chieftain"); break;
								case CLAN_SHAMAN: std::strcat(msgtemp, "Shaman"); break;
								case CLAN_GRUNT: std::strcat(msgtemp, "Grunt"); break;
								case CLAN_PEON: std::strcat(msgtemp, "Peon"); break;
								default:;
								}
							}
							if (status == CLAN_CHIEFTAIN) {
								sprintf(msgtemp, "%s has already on chieftain!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
						}

						clanmember_set_status(account_get_clanmember(friend_acc), CLAN_CHIEFTAIN);
						sprintf(msgtemp, "Successfully change status chieftain for user %s.", text);
						message_send_text(c, message_type_info, c, msgtemp);
					}

					else if (strstart(text, "shaman") == 0) {
						t_connection * dest_c;
						t_account * friend_acc;
						t_server_friendslistreply_status status;
						t_clanmember *member;

						text = skip_command(text);

						if (text[0] == '\0') {
							message_send_text(c, message_type_info, c, "--------------------------------------------------------");
							message_send_text(c, message_type_error, c, "Usage: /clan shaman [username] (no have alias)");
							message_send_text(c, message_type_info, c, "** For change status member to shaman.");
							return 0;
						}

						if (!(friend_acc = accountlist_find_account(text))) { message_send_text(c, message_type_info, c, "That user does not exist."); return 0; }
						if (acc == friend_acc) { message_send_text(c, message_type_error, c, "You can't choose yourself!"); return 0; }
						if (!account_get_clan(friend_acc)) { sprintf(msgtemp, "%s is not members!", text); message_send_text(c, message_type_info, c, msgtemp); return 0; }
						if (clan_get_clantag(account_get_clan(friend_acc)) != clan_get_clantag(clan)) { sprintf(msgtemp, "%s is not members!", text); message_send_text(c, message_type_info, c, msgtemp); return 0; }

						if (member = account_get_clanmember(friend_acc)) {
							char	 status;
							if (status = clanmember_get_status(member)) {
								switch (status) {
								case CLAN_CHIEFTAIN: std::strcat(msgtemp, "Chieftain"); break;
								case CLAN_SHAMAN: std::strcat(msgtemp, "Shaman"); break;
								case CLAN_GRUNT: std::strcat(msgtemp, "Grunt"); break;
								case CLAN_PEON: std::strcat(msgtemp, "Peon"); break;
								default:;
								}
							}
							if (status == CLAN_CHIEFTAIN) {
								sprintf(msgtemp, "%s has already on chieftain! You can't change chieftain to shaman!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
							if (status == CLAN_SHAMAN) {
								sprintf(msgtemp, "%s has already on shaman!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
						}

						clanmember_set_status(account_get_clanmember(friend_acc), CLAN_SHAMAN);
						sprintf(msgtemp, "Successfully change status shaman for user %s.", text);
						message_send_text(c, message_type_info, c, msgtemp);
					}
					else if (strstart(text, "grunt") == 0) {
						t_connection * dest_c;
						t_account * friend_acc;
						t_server_friendslistreply_status status;
						t_clanmember *member;

						text = skip_command(text);

						if (text[0] == '\0') {
							message_send_text(c, message_type_info, c, "--------------------------------------------------------");
							message_send_text(c, message_type_error, c, "Usage: /clan grunt [username] (no have alias)");
							message_send_text(c, message_type_info, c, "** For change status member to grunt.");
							return 0;
						}

						if (!(friend_acc = accountlist_find_account(text))) { message_send_text(c, message_type_info, c, "That user does not exist."); return 0; }
						if (acc == friend_acc) { message_send_text(c, message_type_error, c, "You can't choose yourself!"); return 0; }
						if (clan_get_clanid(account_get_clan(friend_acc)) != clan_get_clanid(clan)) { sprintf(msgtemp, "%s is not members!", text); message_send_text(c, message_type_error, c, msgtemp); return 0; }

						if (member = account_get_clanmember(friend_acc)) {
							char	 status;
							if (status = clanmember_get_status(member)) {
								switch (status) {
								case CLAN_CHIEFTAIN: std::strcat(msgtemp, "Chieftain"); break;
								case CLAN_SHAMAN: std::strcat(msgtemp, "Shaman"); break;
								case CLAN_GRUNT: std::strcat(msgtemp, "Grunt"); break;
								case CLAN_PEON: std::strcat(msgtemp, "Peon"); break;
								default:;
								}
							}
							if (status == CLAN_CHIEFTAIN) {
								sprintf(msgtemp, "%s has already on chieftain! You can't change chieftain to grunt!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
							if (status == CLAN_GRUNT) {
								sprintf(msgtemp, "%s has already on grunt!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
						}

						clanmember_set_status(account_get_clanmember(friend_acc), CLAN_GRUNT);
						sprintf(msgtemp, "Successfully change status grunt for user %s.", text);
						message_send_text(c, message_type_info, c, msgtemp);
					}
					else if (strstart(text, "peon") == 0) {
						t_connection * dest_c;
						t_account * friend_acc;
						t_server_friendslistreply_status status;
						t_clanmember *member;

						text = skip_command(text);

						if (text[0] == '\0') {
							message_send_text(c, message_type_info, c, "--------------------------------------------------------");
							message_send_text(c, message_type_error, c, "Usage: /clan peon [username] (no have alias)");
							message_send_text(c, message_type_info, c, "** For change status member to peon.");
							return 0;
						}

						if (!(friend_acc = accountlist_find_account(text))) { message_send_text(c, message_type_info, c, "That user does not exist."); return 0; }
						if (acc == friend_acc) { message_send_text(c, message_type_error, c, "You can't choose yourself!"); return 0; }
						if (clan_get_clanid(account_get_clan(friend_acc)) != clan_get_clanid(clan)) { sprintf(msgtemp, "%s is not members!", text); message_send_text(c, message_type_error, c, msgtemp); return 0; }

						if (member = account_get_clanmember(friend_acc)) {
							char	 status;
							if (status = clanmember_get_status(member)) {
								switch (status) {
								case CLAN_CHIEFTAIN: std::strcat(msgtemp, "Chieftain"); break;
								case CLAN_SHAMAN: std::strcat(msgtemp, "Shaman"); break;
								case CLAN_GRUNT: std::strcat(msgtemp, "Grunt"); break;
								case CLAN_PEON: std::strcat(msgtemp, "Peon"); break;
								default:;
								}
							}
							if (status == CLAN_CHIEFTAIN) {
								sprintf(msgtemp, "%s has already on chieftain! You can't change chieftain to peon!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
							if (status == CLAN_PEON) {
								sprintf(msgtemp, "%s has already on peon!", text);
								message_send_text(c, message_type_error, c, msgtemp);
								return 0;
							}
						}

						clanmember_set_status(account_get_clanmember(friend_acc), CLAN_PEON);
						sprintf(msgtemp, "Successfully change status peon for user %s.", text);
						message_send_text(c, message_type_info, c, msgtemp);
					}
					else if (strstart(text, "channel") == 0) {
						const char * channel = skip_command(text);
						clan = clanmember_get_clan(member);
						if (channel[0] == '\0') {
							message_send_text(c, message_type_info, c, "--------------------------------------------------------");
							message_send_text(c, message_type_error, c, "Usage: /clan [channel] (no have alias)");
							message_send_text(c, message_type_info, c, "** For change your clan channel.");
							return 0;
						}
						if (clan_set_channel(clan, channel)<0)
							message_send_text(c, message_type_error, c, "Failed to change clan channel!");
						else
							message_send_text(c, message_type_info, c, "Sucsessfully to change you clan channel.");
					}
					else if (strstart(text, "disband") == 0) {
						const char * ack = skip_command(text);
						if (ack[0] == '\0') {
							message_send_text(c, message_type_info, c, "This is one-way action! If you really want");
							message_send_text(c, message_type_info, c, "to disband your clan, type /clan disband yes");
						}
						else if (strstart(ack, "yes") == 0) {
							if (clanlist_remove_clan(clan) == 0) {
								if (clan_get_created(clan) == 1)
									clan_remove(clan_get_clantag(clan));
								clan_destroy(clan);
								message_send_text(c, message_type_info, c, "Your clan was disbanded :(");
							}
						}
					}
				}
			}
			else if ((member = account_get_clanmember_forced(acc)) && (clan = clanmember_get_clan(member)) && (clanmember_get_fullmember(member) == 0)) {
				if (text[0] == '\0') {
					message_send_text(c, message_type_error, c, "-- YOU HAVE CLAN INVITATION -----");
					message_send_text(c, message_type_info, c, "Usage: /clan invite get - for show clanname wich you have been invited.");
					message_send_text(c, message_type_info, c, "Usage: /clan invite accept (alias: acc) - for accept invitation to clan");
					message_send_text(c, message_type_info, c, "Usage: /clan invite decline (alias: dec) - for decline invitation to clan");
				}

				if (strstart(text, "invite") == 0 || strstart(text, "inv") == 0) {
					text = skip_command(text);

					if (text[0] == '\0') {
						message_send_text(c, message_type_error, c, "-- YOU HAVE CLAN INVITATION -----");
						message_send_text(c, message_type_info, c, "Usage: /clan invite get - for show clanname wich you have been invited.");
						message_send_text(c, message_type_info, c, "Usage: /clan invite accept (alias: acc) - for accept invitation to clan");
						message_send_text(c, message_type_info, c, "Usage: /clan invite decline (alias: dec) - for decline invitation to clan");
					}

					else if (strstart(text, "get") == 0) {
						snprintf(msgtemp, sizeof(msgtemp), "You have been invited to %s", clan_get_name(clan));
						message_send_text(c, message_type_info, c, msgtemp);
					}

					else if (strstart(text, "accept") == 0 || strstart(text, "acc") == 0) {
						int created = clan_get_created(clan);

						clanmember_set_fullmember(member, 1);
						clanmember_set_join_time(member, std::time(NULL));
						snprintf(msgtemp, sizeof(msgtemp), "You are now clanmember of %s", clan_get_name(clan));
						message_send_text(c, message_type_info, c, msgtemp);
						if (created > 0) {
							DEBUG1("clan %s has already been created", clan_get_name(clan));
							return 0;
						}
						created++;
						if (created >= 0) {
							clan_set_created(clan, 1);
							clan_set_creation_time(clan, std::time(NULL));
							/* FIXME: send message "CLAN was be created" to members */
							snprintf(msgtemp, sizeof(msgtemp), "Clan %s was be created", clan_get_name(clan));
							clan_send_message_to_online_members(clan, message_type_whisper, c, msgtemp); /* Send message to all members */
							message_send_text(c, message_type_whisper, c, msgtemp);                      /* also to self */
							clan_save(clan);
						}
						else
							clan_set_created(clan, created);
					}

					else if (strstart(text, "decline") == 0 || strstart(text, "dec") == 0) {
						clan_remove_member(clan, member);
						snprintf(msgtemp, sizeof(msgtemp), "You are no longer ivited to %s", clan_get_name(clan));
						message_send_text(c, message_type_info, c, msgtemp);
					}
				}
			}
			else {
				if (text[0] == '\0') {
					message_send_text(c, message_type_info, c, "--------------------------------------------------------");
					message_send_text(c, message_type_error, c, "Usage: /clan create [clantag] [clanname] (alias: cre)");
					message_send_text(c, message_type_info, c, "** For create a new clan.");
				}
				else if (strstart(text, "create") == 0 || strstart(text, "cre") == 0) {
					unsigned int i, j;
					char clantag[CLANSHORT_NAME_MAX + 1];
					char clanname[CLAN_NAME_MAX];

					for (i = 0; text[i] != ' ' && text[i] != '\0'; i++); /* skip command */
					for (; text[i] == ' '; i++);

					for (j = 0; text[i] != ' ' && text[i] != '\0'; i++) /* get clantag */
					if (j<sizeof(clantag)-1) clantag[j++] = text[i];
					clantag[j] = '\0';

					for (; text[i] == ' '; i++);                    /* skip spaces */
					for (j = 0; text[i] != '\0'; i++)                 /* get clanname (spaces are allowed) */
					if (j<sizeof(clanname)-1) clanname[j++] = text[i];
					clanname[j] = '\0';

					if ((clantag[0] == '\0') || (clanname[0] == '\0')) {
						message_send_text(c, message_type_info, c, "--------------------------------------------------------");
						message_send_text(c, message_type_error, c, "Usage: /clan create [clantag] [clanname] (alias: cre)");
						message_send_text(c, message_type_info, c, "** For create a new clan.");
						return 0;
					}

					if ((clan = clan_create(conn_get_account(c), str_to_clantag(clantag), clanname, NULL)) && clanlist_add_clan(clan)) {
						member = account_get_clanmember_forced(acc);
						if (prefs_get_clan_min_invites() == 0) {
							clan_set_created(clan, 1);
							clan_set_creation_time(clan, std::time(NULL));
							snprintf(msgtemp, sizeof(msgtemp), "Clan %s is created!", clan_get_name(clan));
							message_send_text(c, message_type_info, c, msgtemp);
							clan_save(clan);
						}
						else {
							snprintf(msgtemp, sizeof(msgtemp), "Clan %s is pre-created, please invite", clan_get_name(clan));
							message_send_text(c, message_type_info, c, msgtemp);
							snprintf(msgtemp, sizeof(msgtemp), "at last %u players to your clan by using", prefs_get_clan_min_invites());
							message_send_text(c, message_type_info, c, msgtemp);
							message_send_text(c, message_type_info, c, "/clan invite <username> command.");
						}
					}
				}
			}
			return 0;
		}

		static int _handle_admin_command(t_connection * c, char const * text) {
			char const * username;
			char command;
			t_account * acc;
			t_connection * dst_c;
			int changed = 0;

			text = skip_command(text);

			if ((text[0] == '\0') || ((text[0] != '+') && (text[0] != '-'))) {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /admin +[username] (no have alias)");
				message_send_text(c, message_type_info, c, "** For promote user to administrator.");
				message_send_text(c, message_type_error, c, "Usage: /admin -[username] (no have alias)");
				message_send_text(c, message_type_info, c, "** For demote user from administrator.");
				return -1;
			}

			command = text[0];
			username = &text[1];

			if (!*username) {
				message_send_text(c, message_type_error, c, "You need to input a username!");
				return -1;
			}

			if (!(acc = accountlist_find_account(username))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return -1;
			}

			dst_c = account_get_conn(acc);

			if (command == '+') {
				if (account_get_auth_admin(acc, NULL) == 1) {
					snprintf(msgtemp, sizeof(msgtemp), "%.64s has already on administrator.", username);
				}
				else {
					account_set_auth_admin(acc, NULL, 1);
					snprintf(msgtemp, sizeof(msgtemp), "%.64s has been promoted to administrator.", username);
					changed = 1;
				}
			}
			else {
				if (account_get_auth_admin(acc, NULL) != 1)
					snprintf(msgtemp, sizeof(msgtemp), "%.64s is no administrator, so you can't demote him.", username);
				else {
					account_set_auth_admin(acc, NULL, 0);
					snprintf(msgtemp, sizeof(msgtemp), "%.64s has been demoted from administrator.", username);
					changed = 1;
				}
			}

			if (changed && dst_c) message_send_text(dst_c, message_type_info, c, msgtemp2);
			message_send_text(c, message_type_info, c, msgtemp);
			command_set_flags(dst_c);
			return 0;
		}

		static int _handle_operator_command(t_connection * c, char const * text) {
			char const *	username;
			char		command;
			t_account *		acc;
			t_connection *	dst_c;
			int			changed = 0;

			text = skip_command(text);

			if ((text[0] == '\0') || ((text[0] != '+') && (text[0] != '-'))) {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /operator +[username] (no have alias)");
				message_send_text(c, message_type_info, c, "** For promote user to operator.");
				message_send_text(c, message_type_error, c, "Usage: /operator -[username] (no have alias)");
				message_send_text(c, message_type_info, c, "** For demote user from operator.");

				return -1;
			}

			command = text[0];
			username = &text[1];

			if (!*username) {
				message_send_text(c, message_type_info, c, "You need to input a username!");
				return -1;
			}

			if (!(acc = accountlist_find_account(username))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return -1;
			}

			dst_c = account_get_conn(acc);

			if (command == '+') {
				if (account_get_auth_operator(acc, NULL) == 1)
					snprintf(msgtemp, sizeof(msgtemp), "%.64s has already on operator.", username);
				else {
					account_set_auth_operator(acc, NULL, 1);
					snprintf(msgtemp, sizeof(msgtemp), "%.64s has been promoted to operator.", username);
					changed = 1;
				}
			}
			else {
				if (account_get_auth_operator(acc, NULL) != 1)
					snprintf(msgtemp, sizeof(msgtemp), "%.64s is no operator, so you can't demote him.", username);
				else {
					account_set_auth_operator(acc, NULL, 0);
					snprintf(msgtemp, sizeof(msgtemp), "%.64s has been demoted from operator.", username);
					changed = 1;
				}
			}

			if (changed && dst_c) message_send_text(dst_c, message_type_info, c, msgtemp2);
			message_send_text(c, message_type_info, c, msgtemp);
			command_set_flags(dst_c);
			return 0;
		}

		static int _handle_lockacct_command(t_connection * c, char const *text) {
			t_connection * user;
			t_account *    account;

			text = skip_command(text);

			if (text[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /lockacct [username] (no have alias)");
				message_send_text(c, message_type_info, c, "** For locks player's account to prevent him/her from logging in with it.");
				return 0;
			}

			if (!(account = accountlist_find_account(text))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return 0;
			}

			account_set_auth_lock(account, 1);
			snprintf(msgtemp, sizeof(msgtemp), "Successfully for lock account %s.", text);
			message_send_text(c, message_type_info, c, msgtemp);
			return 0;
		}

		static int _handle_unlockacct_command(t_connection * c, char const *text) {
			t_connection * user;
			t_account *    account;

			text = skip_command(text);

			if (text[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /unlockacct [username] (no have alias)");
				message_send_text(c, message_type_info, c, "** For unlocks player's account to allow him/her to log in with it.");
				return 0;
			}

			if (!(account = accountlist_find_account(text))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return 0;
			}

			account_set_auth_lock(account, 0);
			snprintf(msgtemp, sizeof(msgtemp), "Successfully for unlock account %s.", text);
			message_send_text(c, message_type_info, c, msgtemp);
			return 0;
		}

		static int _handle_muteacct_command(t_connection * c, char const *text) {
			t_connection * user;
			t_account *    account;

			text = skip_command(text);

			if (text[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /mute [username] (no have alias)");
				message_send_text(c, message_type_info, c, "** For mutes player's account to prevent him/her from talking on channels.");
				return 0;
			}

			if (!(account = accountlist_find_account(text))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return 0;
			}

			account_set_auth_mute(account, 1);
			snprintf(msgtemp, sizeof(msgtemp), "Successfully for mute account %s.", text);
			message_send_text(c, message_type_info, c, msgtemp);
			return 0;
		}

		static int _handle_unmuteacct_command(t_connection * c, char const *text) {
			t_connection * user;
			t_account *    account;

			text = skip_command(text);

			if (text[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /unmute [username] (no have alias)");
				message_send_text(c, message_type_info, c, "** For unmutes player's account to allow him/her to talk on channels.");
				return 0;
			}

			if (!(account = accountlist_find_account(text))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return 0;
			}

			account_set_auth_mute(account, 0);
			snprintf(msgtemp, sizeof(msgtemp), "Successfully for unmute account %s.", text);
			message_send_text(c, message_type_info, c, msgtemp);
			return 0;
		}

		static int _handle_whois_command(t_connection * c, char const * text) {
			unsigned int i;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);

			if (text[i] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /whois [username] (alias: /whereis /where)");
				message_send_text(c, message_type_info, c, "** For displays where a player's on the server.");
				return 0;
			}

			do_whois(c, &text[i]);
			return 0;
		}

		static int _handle_voice_command(t_connection * c, char const * text) {
			char const *	username;
			char const *	channel;
			t_account *		acc;
			t_connection *	dst_c;
			int			changed = 0;

			if (!(conn_get_channel(c)) || !(channel = channel_get_name(conn_get_channel(c)))) {
				message_send_text(c, message_type_error, c, "This command can only be used inside a channel.");
				return -1;
			}

			if (!(account_is_operator_or_admin(conn_get_account(c), channel_get_name(conn_get_channel(c))))) {
				message_send_text(c, message_type_error, c, "You must be at least a channel operator to use this command.");
				return -1;
			}

			text = skip_command(text);

			if (!(username = &text[0])) {
				message_send_text(c, message_type_info, c, "You need to input a username!");
				return -1;
			}

			if (!(acc = accountlist_find_account(username))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return -1;
			}

			dst_c = account_get_conn(acc);
			if (account_get_auth_voice(acc, channel) == 1)
				snprintf(msgtemp, sizeof(msgtemp), "%.64s is already on vop list, no need to voice him", username);
			else {
				if ((!dst_c) || conn_get_channel(c) != conn_get_channel(dst_c)) {
					snprintf(msgtemp, sizeof(msgtemp), "%.64s must be on the same channel to voice him", username);
				}
				else {
					if (channel_conn_has_tmpVOICE(conn_get_channel(c), dst_c))
						snprintf(msgtemp, sizeof(msgtemp), "%.64s has already Voice in this channel", username);
					else {
						if (account_is_operator_or_admin(acc, channel))
							snprintf(msgtemp, sizeof(msgtemp), "%.64s allready is operator or admin, no need to voice him", username);
						else {
							conn_set_tmpVOICE_channel(dst_c, channel);
							snprintf(msgtemp, sizeof(msgtemp), "%.64s has been granted Voice in this channel", username);
							changed = 1;
						}
					}
				}
			}

			if (changed && dst_c) message_send_text(dst_c, message_type_info, c, msgtemp2);
			message_send_text(c, message_type_info, c, msgtemp);
			command_set_flags(dst_c);
			return 0;
		}

		static int _handle_devoice_command(t_connection * c, char const * text) {
			char const *	username;
			char const *	channel;
			t_account *		acc;
			t_connection *	dst_c;
			int			done = 0;
			int			changed = 0;

			if (!(conn_get_channel(c)) || !(channel = channel_get_name(conn_get_channel(c)))) {
				message_send_text(c, message_type_error, c, "This command can only be used inside a channel.");
				return -1;
			}

			if (!(account_is_operator_or_admin(conn_get_account(c), channel_get_name(conn_get_channel(c))))) {
				message_send_text(c, message_type_error, c, "You must be at least a channel operator to use this command.");
				return -1;
			}

			text = skip_command(text);

			if (!(username = &text[0])) {
				message_send_text(c, message_type_info, c, "You need to input a username!");
				return -1;
			}

			if (!(acc = accountlist_find_account(username))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return -1;
			}

			dst_c = account_get_conn(acc);

			if (account_get_auth_voice(acc, channel) == 1) {
				if ((account_get_auth_admin(conn_get_account(c), channel) == 1) || (account_get_auth_admin(conn_get_account(c), NULL) == 1)) {
					account_set_auth_voice(acc, channel, 0);
					snprintf(msgtemp, sizeof(msgtemp), "%.64s has been removed from vop list.", username);
					changed = 1;
				}
				else {
					snprintf(msgtemp, sizeof(msgtemp), "You must be at least channel admin to remove %.64s from the vop list", username);
				}
				done = 1;
			}

			message_send_text(c, message_type_info, c, msgtemp);
			changed = 0;

			if ((dst_c) && channel_conn_has_tmpVOICE(conn_get_channel(c), dst_c) == 1) {
				conn_set_tmpVOICE_channel(dst_c, NULL);
				snprintf(msgtemp, sizeof(msgtemp), "Voice has been taken from %.64s in this channel", username);
				changed = 1;
				done = 1;
			}

			message_send_text(c, message_type_info, c, msgtemp);

			if (!done) {
				snprintf(msgtemp, sizeof(msgtemp), "%.64s has no Voice in this channel, so it can't be taken away", username);
				message_send_text(c, message_type_info, c, msgtemp);
			}

			command_set_flags(dst_c);
			return 0;
		}

		static int _handle_watch_command(t_connection * c, char const *text) {
			unsigned int i;
			t_account *  account;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);

			if (text[i] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /watch [username] (no have alias)");
				message_send_text(c, message_type_info, c, "** For enables notifications from that username.");
				return 0;
			}

			if (!(account = accountlist_find_account(&text[i]))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return 0;
			}

			if (conn_add_watch(c, account, 0)<0)
				message_send_text(c, message_type_error, c, "Add to watch list failed.");

			else {
				snprintf(msgtemp, sizeof(msgtemp), "User %.64s added to your watch list.", &text[i]);
				message_send_text(c, message_type_info, c, msgtemp);
			}

			return 0;
		}

		static int _handle_unwatch_command(t_connection * c, char const *text)
		{
			unsigned int i;
			t_account *  account;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);

			if (text[i] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /unwatch [username] (no have alias)");
				message_send_text(c, message_type_info, c, "** For disables notifications from that username.");
				return 0;
			}

			if (!(account = accountlist_find_account(&text[i]))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return 0;
			}

			if (conn_del_watch(c, account, 0)<0)
				message_send_text(c, message_type_error, c, "Removal from watch list failed.");

			else {
				snprintf(msgtemp, sizeof(msgtemp), "User %.64s removed from your watch list.", &text[i]);
				message_send_text(c, message_type_info, c, msgtemp);
			}

			return 0;
		}

		static int _handle_watchall_command(t_connection * c, char const *text)
		{
			t_clienttag clienttag = 0;
			char clienttag_str[5];

			text = skip_command(text);

			if (text[0] != '\0') {
				if (std::strlen(text) != 4) {
					message_send_text(c, message_type_error, c, "You must supply a rank and a valid program ID.");
					message_send_text(c, message_type_error, c, "Example: /watchall STAR");
					return 0;
				}
				clienttag = tag_case_str_to_uint(text);
			}

			if (conn_add_watch(c, NULL, clienttag)<0)
				message_send_text(c, message_type_error, c, "Add to watch list failed.");

			else if (clienttag) {
				char msgtemp[MAX_MESSAGE_LEN];
				snprintf(msgtemp, sizeof(msgtemp), "All %.128s users added to your watch list.", tag_uint_to_str(clienttag_str, clienttag));
				message_send_text(c, message_type_info, c, msgtemp);
			}
			else
				message_send_text(c, message_type_info, c, "All users added to your watch list.");
			return 0;
		}

		static int _handle_unwatchall_command(t_connection * c, char const *text) {
			t_clienttag clienttag = 0;
			char clienttag_str[5];

			text = skip_command(text);

			if (text[0] != '\0') {
				if (std::strlen(text) != 4) {
					message_send_text(c, message_type_error, c, "You must supply a rank and a valid program ID.");
					message_send_text(c, message_type_error, c, "Example: /unwatchall STAR");
				}
				clienttag = tag_case_str_to_uint(text);
			}

			if (conn_del_watch(c, NULL, clienttag)<0)
				message_send_text(c, message_type_error, c, "Removal from watch list failed.");

			else if (clienttag) {
				char msgtemp[MAX_MESSAGE_LEN];
				snprintf(msgtemp, sizeof(msgtemp), "All %.128s users removed from your watch list.", tag_uint_to_str(clienttag_str, clienttag));
				message_send_text(c, message_type_info, c, msgtemp);
			}
			else
				message_send_text(c, message_type_info, c, "All users removed from your watch list.");

			return 0;
		}

		static int _handle_whisper_command(t_connection * c, char const *text) {
			char         dest[MAX_USERNAME_LEN + MAX_REALMNAME_LEN];
			unsigned int i, j;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++)
			if (j<sizeof(dest)-1) dest[j++] = text[i];
			dest[j] = '\0';
			for (; text[i] == ' '; i++);

			if ((dest[0] == '\0') || (text[i] == '\0')) {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /msg [username] [message] (alias: /w /m /whisper)");
				message_send_text(c, message_type_info, c, "** For sends a private message to player.");
				return 0;
			}

			do_whisper(c, dest, &text[i]);
			return 0;
		}

		static int _handle_botchatblue_command(t_connection * c, char const *text) {
			char         dest[MAX_USERNAME_LEN + MAX_REALMNAME_LEN];
			unsigned int i, j;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++)
			if (j<sizeof(dest)-1) dest[j++] = text[i];
			dest[j] = '\0';
			for (; text[i] == ' '; i++);

			if ((dest[0] == '\0') || (text[i] == '\0')) {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /botchatblue [username] [message] (no have alias)");
				message_send_text(c, message_type_info, c, "** For sends a private message to player.");
				return 0;
			}

			do_botchatblue(c, dest, &text[i]);
			return 0;
		}

		static int _handle_botchatred_command(t_connection * c, char const *text) {
			char         dest[MAX_USERNAME_LEN + MAX_REALMNAME_LEN];
			unsigned int i, j;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++)
			if (j<sizeof(dest)-1) dest[j++] = text[i];
			dest[j] = '\0';
			for (; text[i] == ' '; i++);

			if ((dest[0] == '\0') || (text[i] == '\0')) {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /botchatred [username] [message] (no have alias)");
				message_send_text(c, message_type_info, c, "** For sends a private message to player.");
				return 0;
			}

			do_botchatred(c, dest, &text[i]);
			return 0;
		}

		static int _handle_users_command(t_connection * c, char const *text) {
			char ctag[5];
			unsigned int i, j;
			t_clienttag clienttag;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++); /* skip command */
			for (; text[i] == ' '; i++);
			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++) /* get clienttag */
			if (j<sizeof(ctag)-1) ctag[j++] = text[i];
			ctag[j] = '\0';

			if (ctag[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "There are currently %d users online, in %d games and %d channels.",
					connlist_login_get_length(),
					gamelist_get_length(),
					channellist_get_length());
				message_send_text(c, message_type_info, c, msgtemp);
				tag_uint_to_str(ctag, conn_get_clienttag(c));
			}

			else {
				snprintf(msgtemp, sizeof(msgtemp), "There are currently %d users online, in %d games and %d channels.",
					connlist_login_get_length(),
					gamelist_get_length(),
					channellist_get_length());
				message_send_text(c, message_type_info, c, msgtemp);
				tag_uint_to_str(ctag, conn_get_clienttag(c));
			}
			return 0;
		}

		static int _handle_quit_command(t_connection * c, char const *text)
		{
			if (conn_get_game(c))
				eventlog(eventlog_level_warn, __FUNCTION__, "[%d] user '%s' tried to disconnect while in game, cheat attempt ?", conn_get_socket(c), conn_get_loggeduser(c));
			else {
				message_send_text(c, message_type_info, c, "Thanks for playing today, see you tomorrow :)");
				conn_set_state(c, conn_state_destroy);
			}

			return 0;
		}

		static int _handle_squelch_command(t_connection * c, char const *text) {
			t_account *  account;

			text = skip_command(text);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /squelch [username] (alias: /ignore)");
				message_send_text(c, message_type_info, c, "** For blocks future messages sent from username.");
				return 0;
			}

			if (!(account = accountlist_find_account(text))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return 0;
			}

			if (conn_get_account(c) == account) {
				message_send_text(c, message_type_error, c, "You can't squelch yourself.");
				return 0;
			}

			if (conn_add_ignore(c, account)<0)
				message_send_text(c, message_type_error, c, "Could not squelch user.");
			else {
				snprintf(msgtemp, sizeof(msgtemp), "%-.20s has been squelched.", account_get_name(account));
				message_send_text(c, message_type_info, c, msgtemp);
			}

			return 0;
		}

		static int _handle_unsquelch_command(t_connection * c, char const *text) {
			t_account * account;
			t_connection * dest_c;

			text = skip_command(text);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /unsquelch [username] (alias: /unignore)");
				message_send_text(c, message_type_info, c, "** For allows a previously squelched player to talk to you normally.");
				return 0;
			}

			if (!(account = accountlist_find_account(text))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return 0;
			}

			if (conn_del_ignore(c, account)<0)
				message_send_text(c, message_type_info, c, "User was not being ignored.");
			else {
				t_message * message;
				message_send_text(c, message_type_info, c, "No longer ignoring.");

				if ((dest_c = account_get_conn(account))) {
					if (!(message = message_create(message_type_userflags, dest_c, NULL))) /* handles NULL text */
						return 0;

					message_send(message, c);
					message_destroy(message);
				}
			}
			return 0;
		}

		static int _handle_tmpop_command(t_connection * c, char const * text) {
			char const *	username;
			char const *	channel;
			t_account *		acc;
			t_connection *	dst_c;
			int			changed = 0;

			text = skip_command(text);

			if (!(account_is_operator_or_admin(conn_get_account(c), channel_get_name(conn_get_channel(c))) || channel_conn_is_tmpOP(conn_get_channel(c), c))) {
				message_send_text(c, message_type_error, c, "You must be at least a channel operator or tmpOP to use this command.");
				return -1;
			}

			if (!(username = &text[0])) {
				message_send_text(c, message_type_info, c, "You need to input a username!");
				return -1;
			}

			if (!(conn_get_channel(c)) || !(channel = channel_get_name(conn_get_channel(c)))) {
				message_send_text(c, message_type_error, c, "This command can only be used inside a channel.");
				return -1;
			}

			if (!(acc = accountlist_find_account(username))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return -1;
			}

			dst_c = account_get_conn(acc);

			if (channel_conn_is_tmpOP(conn_get_channel(c), dst_c))
				snprintf(msgtemp, sizeof(msgtemp), "%.64s has already tmpOP in this channel", username);
			else
			{
				if ((!(dst_c)) || (conn_get_channel(c) != conn_get_channel(dst_c)))
					snprintf(msgtemp, sizeof(msgtemp), "%.64s must be on the same channel to tempOP him", username);
				else {
					if (account_is_operator_or_admin(acc, channel))
						snprintf(msgtemp, sizeof(msgtemp), "%.64s already is operator or admin, no need to tempOP him", username);
					else {
						conn_set_tmpOP_channel(dst_c, channel);
						snprintf(msgtemp, sizeof(msgtemp), "%.64s has been promoted to tmpOP in this channel", username);
						changed = 1;
					}
				}
			}

			if (changed && dst_c) message_send_text(dst_c, message_type_info, c, msgtemp2);
			message_send_text(c, message_type_info, c, msgtemp);
			command_set_flags(dst_c);
			return 0;
		}

		static int _handle_deop_command(t_connection * c, char const * text) {
			char const *	username;
			char const *	channel;
			t_account *		acc;
			int			OP_lvl;
			t_connection *	dst_c;
			int			done = 0;

			if (!(conn_get_channel(c)) || !(channel = channel_get_name(conn_get_channel(c)))) {
				message_send_text(c, message_type_error, c, "This command can only be used inside a channel.");
				return -1;
			}

			acc = conn_get_account(c);
			OP_lvl = 0;

			if (account_is_operator_or_admin(acc, channel))
				OP_lvl = 1;
			else if (channel_conn_is_tmpOP(conn_get_channel(c), account_get_conn(acc)))
				OP_lvl = 2;

			if (OP_lvl == 0) {
				message_send_text(c, message_type_error, c, "You must be at least a channel operator or tempOP to use this command.");
				return -1;
			}

			text = skip_command(text);

			if (!(username = &text[0])) {
				message_send_text(c, message_type_info, c, "You need to input a username!");
				return -1;
			}

			if (!(acc = accountlist_find_account(username))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return -1;
			}

			dst_c = account_get_conn(acc);

			if (OP_lvl == 1) {
				if (account_get_auth_admin(acc, channel) == 1 || account_get_auth_operator(acc, channel) == 1) {
					if (account_get_auth_admin(acc, channel) == 1) {
						if (account_get_auth_admin(conn_get_account(c), channel) != 1 && account_get_auth_admin(conn_get_account(c), NULL) != 1)
							message_send_text(c, message_type_info, c, "You must be at least a channel admin to demote another channel admin");
						else {
							account_set_auth_admin(acc, channel, 0);
							snprintf(msgtemp, sizeof(msgtemp), "%.64s has been demoted from a channel admin.", username);
							message_send_text(c, message_type_info, c, msgtemp);
						}
					}
					if (account_get_auth_operator(acc, channel) == 1) {
						account_set_auth_operator(acc, channel, 0);
						snprintf(msgtemp, sizeof(msgtemp), "%.64s has been demoted from a channel operator", username);
						message_send_text(c, message_type_info, c, msgtemp);
					}
					done = 1;
				}
				if ((dst_c) && channel_conn_is_tmpOP(conn_get_channel(c), dst_c)) {
					conn_set_tmpOP_channel(dst_c, NULL);
					snprintf(msgtemp, sizeof(msgtemp), "%.64s has been demoted from a tempOP of this channel", username);
					message_send_text(c, message_type_info, c, msgtemp);
					done = 1;
				}
				if (!done) {
					snprintf(msgtemp, sizeof(msgtemp), "%.64s is no channel admin or channel operator or tempOP, so you can't demote him.", username);
					message_send_text(c, message_type_info, c, msgtemp);
				}
			}
			else {
				if (dst_c && channel_conn_is_tmpOP(conn_get_channel(c), dst_c)) {
					conn_set_tmpOP_channel(account_get_conn(acc), NULL);
					snprintf(msgtemp, sizeof(msgtemp), "%.64s has been demoted from a tempOP of this channel", username);
					message_send_text(c, message_type_info, c, msgtemp);
					snprintf(msgtemp2, sizeof(msgtemp2), "%.64s has demoted you from a tempOP of channel \"%.128s\"", conn_get_loggeduser(c), channel);
				}
				else {
					snprintf(msgtemp, sizeof(msgtemp), "%.64s is no tempOP in this channel, so you can't demote him", username);
					message_send_text(c, message_type_info, c, msgtemp);
				}
			}

			command_set_flags(connlist_find_connection_by_accountname(username));
			return 0;
		}

		static int _handle_join_command(t_connection * c, char const *text) {
			t_channel * channel;
			text = skip_command(text);

			if ((conn_get_clienttag(c) == CLIENTTAG_WARCRAFT3_UINT) || (conn_get_clienttag(c) == CLIENTTAG_WAR3XP_UINT)) {
				if (text[0] == '\0') {
					message_send_text(c, message_type_info, c, "--------------------------------------------------------");
					message_send_text(c, message_type_error, c, "Usage: /join [channel] (no have alias)");
					message_send_text(c, message_type_info, c, "** For moves you to channel.");
					return 0;
				}

				if (!conn_get_game(c)) {
					if (strcasecmp(text, "Arranged Teams") == 0) {
						message_send_text(c, message_type_error, c, "Channel Arranged Teams is a RESTRICTED Channel!");
						return 0;
					}

					if (!(std::strlen(text) < MAX_CHANNELNAME_LEN)) {
						snprintf(msgtemp, sizeof(msgtemp), "max channel name length exceeded (max %d symbols)", MAX_CHANNELNAME_LEN - 1);
						message_send_text(c, message_type_error, c, msgtemp);
						return 0;
					}
					if ((channel = conn_get_channel(c)) && (strcasecmp(channel_get_name(channel), text) == 0))
						return 0; // we don't have to do anything, we are allready in this channel

					if (conn_set_channel(c, text)<0)
						conn_set_channel(c, CHANNEL_NAME_BANNED); /* should not fail */
					if ((conn_get_clienttag(c) == CLIENTTAG_WARCRAFT3_UINT) || (conn_get_clienttag(c) == CLIENTTAG_WAR3XP_UINT))
						conn_update_w3_playerinfo(c);
					command_set_flags(c);
				}
				else
					message_send_text(c, message_type_error, c, "Command disabled while inside a game.");
				return 0;
			}
			else {
				message_send_text(c, message_type_error, c, "You don't have access to that command!");
				return 0;
			}
			return 0;
		}

		static int _handle_rejoin_command(t_connection * c, char const *text)
		{
			if (channel_rejoin(c) != 0)
				message_send_text(c, message_type_error, c, "You are not in a channel.");
			if ((conn_get_clienttag(c) == CLIENTTAG_WARCRAFT3_UINT) || (conn_get_clienttag(c) == CLIENTTAG_WAR3XP_UINT))
				conn_update_w3_playerinfo(c);
			command_set_flags(c);
			return 0;
		}

		static int _handle_announceblue_command(t_connection * c, char const *text) {
			unsigned int i;
			t_message *  message;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);

			if (text[i] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /announceblue [message] (no have alias)");
				message_send_text(c, message_type_info, c, "** For announces message to all online users with type info.");
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "%s", &text[i]);
			if (!(message = message_create(message_type_info, c, msgtemp)))
				message_send_text(c, message_type_info, c, "Could not broadcast message.");
			else {
				if (message_send_all(message)<0)
					message_send_text(c, message_type_info, c, "Could not broadcast message.");
				message_destroy(message);
			}
			return 0;
		}

		static int _handle_announcered_command(t_connection * c, char const *text) {
			unsigned int i;
			t_message *  message;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);

			if (text[i] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /announcered [message] (no have alias)");
				message_send_text(c, message_type_info, c, "** For announces message to all online users with type error.");
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "%s", &text[i]);
			if (!(message = message_create(message_type_error, c, msgtemp)))
				message_send_text(c, message_type_info, c, "Could not broadcast message.");
			else {
				if (message_send_all(message)<0)
					message_send_text(c, message_type_info, c, "Could not broadcast message.");
				message_destroy(message);
			}
			return 0;
		}

		static int _handle_away_command(t_connection * c, char const *text) {
			text = skip_command(text);
			if (text[0] == '\0') {
				if (!conn_get_awaystr(c)) {
					message_send_text(c, message_type_info, c, "You are now marked as being away.");
					conn_set_awaystr(c, "Currently not available");
				}
				else {
					message_send_text(c, message_type_info, c, "You are no longer marked as away.");
					conn_set_awaystr(c, NULL);
				}
			}
			else {
				message_send_text(c, message_type_info, c, "You are now marked as being away.");
				conn_set_awaystr(c, text);
			}
			return 0;
		}

		static int _handle_dnd_command(t_connection * c, char const *text) {
			text = skip_command(text);
			if (text[0] == '\0') {
				if (!conn_get_dndstr(c)) {
					message_send_text(c, message_type_info, c, "Do Not Disturb mode engaged.");
					conn_set_dndstr(c, "Not available");
				}
				else {
					message_send_text(c, message_type_info, c, "Do Not Disturb mode cancelled.");
					conn_set_dndstr(c, NULL);
				}
			}
			else {
				message_send_text(c, message_type_info, c, "Do Not Disturb mode engaged.");
				conn_set_dndstr(c, text);
			}
			return 0;
		}

		static int _handle_time_command(t_connection * c, char const *text) {
			t_bnettime  btsystem;
			t_bnettime  btlocal;
			std::time_t      now;
			struct std::tm * tmnow;

			btsystem = bnettime();
			btlocal = bnettime_add_tzbias(btsystem, local_tzbias());
			now = bnettime_to_time(btlocal);
			if (!(tmnow = std::gmtime(&now)))
				std::strcpy(msgtemp, "Time: ?");
			else
				std::strftime(msgtemp, sizeof(msgtemp), "Time: %a, %d %b %Y %H:%M:%S", tmnow);
			message_send_text(c, message_type_info, c, msgtemp);
			return 0;
		}

		static int _handle_me_command(t_connection * c, char const * text) {
			t_channel const * channel;
			text = skip_command(text);

			if (text[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /me [message] (no have alias)");
				message_send_text(c, message_type_info, c, "** For send a message via emote.");
				return 0;
			}

			if (!(channel = conn_get_channel(c))) {
				message_send_text(c, message_type_error, c, "You are not in a channel.");
				return 0;
			}

			if ((text[0] != '\0') && (!conn_quota_exceeded(c, text)))
				channel_message_send(channel, message_type_emote, c, text);
			return 0;
		}

		static int _handle_whoami_command(t_connection * c, char const *text) {
			char const * tname;

			if (!(tname = conn_get_username(c)))
			{
				message_send_text(c, message_type_error, c, "Unable to obtain your account name.");
				return 0;
			}

			do_whois(c, tname);

			return 0;
		}

		static int _handle_flag_command(t_connection * c, char const *text) {
			char         dest[32];
			unsigned int i, j;
			unsigned int newflag;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++); /* skip command */
			for (; text[i] == ' '; i++);
			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++) /* get dest */

			if (j<sizeof(dest)-1) dest[j++] = text[i];
			dest[j] = '\0';
			for (; text[i] == ' '; i++);

			if (dest[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /flag [flag] (no have alias)");
				message_send_text(c, message_type_info, c, "** For change your flag.");
				return 0;
			}

			newflag = std::strtoul(dest, NULL, 0);
			conn_set_flags(c, newflag);

			snprintf(msgtemp, sizeof(msgtemp), "Flags set to 0x%08x.", newflag);
			message_send_text(c, message_type_info, c, msgtemp);
			return 0;
		}

		static int _handle_moderate_command(t_connection * c, char const * text) {
			unsigned oldflags;
			t_channel * channel;

			if (!(channel = conn_get_channel(c))) {
				message_send_text(c, message_type_error, c, "This command can only be used inside a channel.");
				return -1;
			}

			if (!(account_is_operator_or_admin(conn_get_account(c), channel_get_name(channel)))) {
				message_send_text(c, message_type_error, c, "You must be at least a channel operator to use this command.");
				return -1;
			}

			oldflags = channel_get_flags(channel);

			if (channel_set_flags(channel, oldflags ^ channel_flags_moderated)) {
				eventlog(eventlog_level_error, __FUNCTION__, "could not set channel %s flags", channel_get_name(channel));
				message_send_text(c, message_type_error, c, "Unable to change channel flags.");
				return -1;
			}
			else {
				if (oldflags & channel_flags_moderated)
					channel_message_send(channel, message_type_info, c, "Channel is now unmoderated");
				else
					channel_message_send(channel, message_type_info, c, "Channel is now moderated");
			}
			return 0;
		}


		static int _handle_commandgroups_command(t_connection * c, char const * text) {
			t_account *	account;
			char *	command;
			char *	username;
			unsigned int usergroups;	// from user account
			unsigned int groups = 0;	// converted from arg3
			char	tempgroups[9];	// converted from usergroups
			char 	t[MAX_MESSAGE_LEN];
			unsigned int i, j;
			char	arg1[256];
			char	arg2[256];
			char	arg3[256];

			std::strncpy(t, text, MAX_MESSAGE_LEN - 1);
			for (i = 0; t[i] != ' ' && t[i] != '\0'; i++);
			for (; t[i] == ' '; i++);
			for (j = 0; t[i] != ' ' && t[i] != '\0'; i++)
			if (j<sizeof(arg1)-1) arg1[j++] = t[i];
			arg1[j] = '\0';

			for (; t[i] == ' '; i++);
			for (j = 0; t[i] != ' ' && t[i] != '\0'; i++)
			if (j<sizeof(arg2)-1) arg2[j++] = t[i];
			arg2[j] = '\0';

			for (; t[i] == ' '; i++);
			for (j = 0; t[i] != '\0'; i++)
			if (j<sizeof(arg3)-1) arg3[j++] = t[i];
			arg3[j] = '\0';

			command = arg1;
			username = arg2;

			if (arg1[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /cg add [username] [groups] (alias: a)");
				message_send_text(c, message_type_info, c, "** For adds command group(s) [groups] to username.");
				message_send_text(c, message_type_error, c, "Usage: /cg del [username] [groups] (alias: d)");
				message_send_text(c, message_type_info, c, "** For deletes command group(s) [groups] from username.");
				message_send_text(c, message_type_error, c, "Usage: /cg list [username] (alias: l)");
				message_send_text(c, message_type_info, c, "** For displays username command groups.");
				return 0;
			}

			if (!std::strcmp(command, "help") || !std::strcmp(command, "h")) {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /cg add [username] [groups] (alias: a)");
				message_send_text(c, message_type_info, c, "** For adds command group(s) [groups] to username.");
				message_send_text(c, message_type_error, c, "Usage: /cg del [username] [groups] (alias: d)");
				message_send_text(c, message_type_info, c, "** For deletes command group(s) [groups] from username.");
				message_send_text(c, message_type_error, c, "Usage: /cg list [username] (alias: l)");
				message_send_text(c, message_type_info, c, "** For displays username command groups.");
				return 0;
			}

			if (arg2[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /cg add [username] [groups] (alias: a)");
				message_send_text(c, message_type_info, c, "** For adds command group(s) [groups] to username.");
				message_send_text(c, message_type_error, c, "Usage: /cg del [username] [groups] (alias: d)");
				message_send_text(c, message_type_info, c, "** For deletes command group(s) [groups] from username.");
				message_send_text(c, message_type_error, c, "Usage: /cg list [username] (alias: l)");
				message_send_text(c, message_type_info, c, "** For displays username command groups.");
				return 0;
			}

			if (!(account = accountlist_find_account(username))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return 0;
			}

			usergroups = account_get_command_groups(account);

			if (!std::strcmp(command, "list") || !std::strcmp(command, "l")) {
				if (usergroups & 1) tempgroups[0] = '1'; else tempgroups[0] = ' ';
				if (usergroups & 2) tempgroups[1] = '2'; else tempgroups[1] = ' ';
				if (usergroups & 4) tempgroups[2] = '3'; else tempgroups[2] = ' ';
				if (usergroups & 8) tempgroups[3] = '4'; else tempgroups[3] = ' ';
				if (usergroups & 16) tempgroups[4] = '5'; else tempgroups[4] = ' ';
				if (usergroups & 32) tempgroups[5] = '6'; else tempgroups[5] = ' ';
				if (usergroups & 64) tempgroups[6] = '7'; else tempgroups[6] = ' ';
				if (usergroups & 128) tempgroups[7] = '8'; else tempgroups[7] = ' ';
				tempgroups[8] = '\0';
				snprintf(msgtemp, sizeof(msgtemp), "%.64s's command group(s): %.64s", username, tempgroups);
				message_send_text(c, message_type_info, c, msgtemp);
				return 0;
			}

			if (arg3[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /cg add [username] [groups] (alias: a)");
				message_send_text(c, message_type_info, c, "** For adds command group(s) [groups] to username.");
				message_send_text(c, message_type_error, c, "Usage: /cg del [username] [groups] (alias: d)");
				message_send_text(c, message_type_info, c, "** For deletes command group(s) [groups] from username.");
				message_send_text(c, message_type_error, c, "Usage: /cg list [username] (alias: l)");
				message_send_text(c, message_type_info, c, "** For displays username command groups.");
				return 0;
			}

			for (i = 0; arg3[i] != '\0'; i++) {
				if (arg3[i] == '1') groups |= 1;
				else if (arg3[i] == '2') groups |= 2;
				else if (arg3[i] == '3') groups |= 4;
				else if (arg3[i] == '4') groups |= 8;
				else if (arg3[i] == '5') groups |= 16;
				else if (arg3[i] == '6') groups |= 32;
				else if (arg3[i] == '7') groups |= 64;
				else if (arg3[i] == '8') groups |= 128;
				else {
					snprintf(msgtemp, sizeof(msgtemp), "got bad group: %c", arg3[i]);
					message_send_text(c, message_type_info, c, msgtemp);
					return 0;
				}
			}

			if (!std::strcmp(command, "add") || !std::strcmp(command, "a")) {
				account_set_command_groups(account, usergroups | groups);
				snprintf(msgtemp, sizeof(msgtemp), "groups %.64s has been added to user: %.64s", arg3, username);
				message_send_text(c, message_type_info, c, msgtemp);
				return 0;
			}

			if (!std::strcmp(command, "del") || !std::strcmp(command, "d")) {
				account_set_command_groups(account, usergroups & (255 - groups));
				snprintf(msgtemp, sizeof(msgtemp), "groups %.64s has been deleted from user: %.64s", arg3, username);
				message_send_text(c, message_type_info, c, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "got unknown command: %.128s", command);
			message_send_text(c, message_type_info, c, msgtemp);
			return 0;
		}

		static int _handle_set_command(t_connection * c, char const *text) {
			t_account * account;
			char *accname;
			char *key;
			char *value;
			char t[MAX_MESSAGE_LEN];
			unsigned int i, j;
			char         arg1[256];
			char         arg2[256];
			char         arg3[256];

			std::strncpy(t, text, MAX_MESSAGE_LEN - 1);
			for (i = 0; t[i] != ' ' && t[i] != '\0'; i++);

			for (; t[i] == ' '; i++);
			for (j = 0; t[i] != ' ' && t[i] != '\0'; i++)
			if (j<sizeof(arg1)-1) arg1[j++] = t[i];
			arg1[j] = '\0';

			for (; t[i] == ' '; i++);
			for (j = 0; t[i] != ' ' && t[i] != '\0'; i++)
			if (j<sizeof(arg2)-1) arg2[j++] = t[i];
			arg2[j] = '\0';

			for (; t[i] == ' '; i++);
			for (j = 0; t[i] != '\0'; i++)
			if (j<sizeof(arg3)-1) arg3[j++] = t[i];
			arg3[j] = '\0';

			accname = arg1;
			key = arg2;
			value = arg3;

			if ((arg1[0] == '\0') || (arg2[0] == '\0')) {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /set [username] [key] [value] (no have alias)");
				message_send_text(c, message_type_info, c, "** For sets or returns the value of <key> for that account.");
			}

			if (!(account = accountlist_find_account(accname))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return 0;
			}

			if (*value == '\0') {
				if (account_get_strattr(account, key)) {
					snprintf(msgtemp, sizeof(msgtemp), "current value of %.64s is \"%.128s\"", key, account_get_strattr(account, key));
					message_send_text(c, message_type_error, c, msgtemp);
				}
				else
					message_send_text(c, message_type_error, c, "value currently not set");
				return 0;
			}

			if (account_set_strattr(account, key, value)<0)
				message_send_text(c, message_type_error, c, "Unable to set key");
			else {
				message_send_text(c, message_type_error, c, "Key set succesfully");
			}
			return 0;
		}

		static int _handle_addacct_command(t_connection * c, char const *text) {
			unsigned int i, j;
			t_account  * temp;
			t_hash       passhash;
			char         username[MAX_USERNAME_LEN];
			char         pass[256];

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);

			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++)
			if (j<sizeof(username)-1) username[j++] = text[i];
			username[j] = '\0';

			for (; text[i] == ' '; i++);
			for (j = 0; text[i] != '\0'; i++)
			if (j<sizeof(pass)-1) pass[j++] = text[i];
			pass[j] = '\0';

			if (username[0] == '\0' || pass[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /addacct [username] [password] (no have alias)");
				message_send_text(c, message_type_info, c, "** For creates a new account players.");
				return 0;
			}

			if (account_check_name(username)<0) {
				message_send_text(c, message_type_error, c, "Account name contains some invalid symbol!");
				return 0;
			}

			for (i = 0; i<std::strlen(pass); i++)
			if (std::isupper((int)pass[i])) pass[i] = std::tolower((int)pass[i]);

			bnet_hash(&passhash, std::strlen(pass), pass);
			temp = accountlist_create_account(username, hash_get_str(passhash));
			if (!temp) {
				message_send_text(c, message_type_error, c, "That account has registered on server!");
				eventlog(eventlog_level_debug, __FUNCTION__, "[%d] account \"%s\" not created (failed)", conn_get_socket(c), username);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "Successfully to create account \"%.64s\" with password \"%.128s\".", username, pass);
			message_send_text(c, message_type_info, c, msgtemp);
			snprintf(msgtemp, sizeof(msgtemp), "ID Registration: "UID_FORMAT".", account_get_uid(temp));
			message_send_text(c, message_type_info, c, msgtemp);
			eventlog(eventlog_level_debug, __FUNCTION__, "[%d] account \"%s\" created", conn_get_socket(c), username);

			return 0;
		}

		static int _handle_chpass_command(t_connection * c, char const *text) {
			unsigned int i, j;
			t_account  * account;
			t_account  * temp;
			t_hash       passhash;
			char         arg1[256];
			char         arg2[256];
			char const * username;
			char *       pass;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);

			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++)
			if (j<sizeof(arg1)-1) arg1[j++] = text[i];
			arg1[j] = '\0';

			for (; text[i] == ' '; i++);
			for (j = 0; text[i] != '\0'; i++)
			if (j<sizeof(arg2)-1) arg2[j++] = text[i];
			arg2[j] = '\0';

			if (arg2[0] == '\0') {
				username = conn_get_username(c);
				pass = arg1;
			}
			else {
				username = arg1;
				pass = arg2;
			}

			if (pass[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /chpass [password] (no have alias)");
				message_send_text(c, message_type_info, c, "** For changes your password to [password].");
				return 0;
			}

			temp = accountlist_find_account(username);
			account = conn_get_account(c);

			if ((temp == account && account_get_auth_changepass(account) == 0) || (temp != account && !(account_get_command_groups(conn_get_account(c)) & command_get_group("/admin-chpass")))) {
				eventlog(eventlog_level_info, __FUNCTION__, "[%d] password change for \"%s\" refused (no change access)", conn_get_socket(c), username);
				message_send_text(c, message_type_error, c, "Only admins may change passwords for other accounts.");
				return 0;
			}

			if (!temp) {
				message_send_text(c, message_type_error, c, "Account does not exist.");
				return 0;
			}

			if (std::strlen(pass) > MAX_USERPASS_LEN) {
				snprintf(msgtemp, sizeof(msgtemp), "Maximum password length allowed is %d", MAX_USERPASS_LEN);
				message_send_text(c, message_type_error, c, msgtemp);
				return 0;
			}

			for (i = 0; i<std::strlen(pass); i++)
			if (std::isupper((int)pass[i])) pass[i] = std::tolower((int)pass[i]);

			bnet_hash(&passhash, std::strlen(pass), pass);

			snprintf(msgtemp, sizeof(msgtemp), "Trying to change password for account \"%.64s\" to \"%.128s\"", username, pass);
			message_send_text(c, message_type_info, c, msgtemp);

			if (account_set_pass(temp, hash_get_str(passhash))<0) {
				message_send_text(c, message_type_error, c, "Unable to set password.");
				return 0;
			}

			if (account_get_auth_admin(account, NULL) == 1 || account_get_auth_operator(account, NULL) == 1) {
				snprintf(msgtemp, sizeof(msgtemp), "Password for account "UID_FORMAT" updated.", account_get_uid(temp));
				message_send_text(c, message_type_info, c, msgtemp);
				snprintf(msgtemp, sizeof(msgtemp), "Hash is: %.128s", hash_get_str(passhash));
				message_send_text(c, message_type_info, c, msgtemp);
			}
			else {
				snprintf(msgtemp, sizeof(msgtemp), "Password for account %.64s updated.", username);
				message_send_text(c, message_type_info, c, msgtemp);
			}
			return 0;
		}

		static int _handle_kick_command(t_connection * c, char const *text) {
			char              dest[MAX_USERNAME_LEN];
			unsigned int      i, j;
			t_channel const * channel;
			t_connection *    kuc;
			t_account *	    acc;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++)
			if (j<sizeof(dest)-1) dest[j++] = text[i];
			dest[j] = '\0';
			for (; text[i] == ' '; i++);

			if (dest[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /kick [username] (no have alias)");
				message_send_text(c, message_type_info, c, "** For kicks player from the channel.");
				return 0;
			}

			if (!(channel = conn_get_channel(c))) {
				message_send_text(c, message_type_error, c, "This command can only be used inside a channel.");
				return 0;
			}

			acc = conn_get_account(c);
			if (account_get_auth_admin(acc, NULL) != 1 && account_get_auth_admin(acc, channel_get_name(channel)) != 1 && account_get_auth_operator(acc, NULL) != 1 && account_get_auth_operator(acc, channel_get_name(channel)) != 1 && !channel_conn_is_tmpOP(channel, account_get_conn(acc))) {
				message_send_text(c, message_type_error, c, "You have to be at least a Channel Operator or tempOP to use this command.");
				return 0;
			}
			if (!(kuc = connlist_find_connection_by_accountname(dest))) {
				message_send_text(c, message_type_error, c, "That user is not logged in.");
				return 0;
			}
			if (conn_get_channel(kuc) != channel) {
				message_send_text(c, message_type_error, c, "That user is not in this channel.");
				return 0;
			}
			if (account_get_auth_admin(conn_get_account(kuc), NULL) == 1 || account_get_auth_admin(conn_get_account(kuc), channel_get_name(channel)) == 1) {
				message_send_text(c, message_type_error, c, "You cannot kick administrators.");
				return 0;
			}
			else if (account_get_auth_operator(conn_get_account(kuc), NULL) == 1 || account_get_auth_operator(conn_get_account(kuc), channel_get_name(channel)) == 1) {
				message_send_text(c, message_type_error, c, "You cannot kick operators.");
				return 0;
			}

			{
				char const * tname1;
				char const * tname2;
				tname1 = conn_get_loggeduser(kuc);
				tname2 = conn_get_loggeduser(c);

				if (!tname1 || !tname2) {
					eventlog(eventlog_level_error, __FUNCTION__, "got NULL username");
					return -1;
				}

				if (text[i] != '\0')
					snprintf(msgtemp, sizeof(msgtemp), "%-.20s has been kicked by %-.20s (%.128s).", tname1, tname2, &text[i]);
				else
					snprintf(msgtemp, sizeof(msgtemp), "%-.20s has been kicked by %-.20s.", tname1, tname2);
				channel_message_send(channel, message_type_info, c, msgtemp);
			}

			conn_kick_channel(kuc, "Bye");
			if (conn_get_class(kuc) == conn_class_bnet)
				conn_set_channel(kuc, CHANNEL_NAME_KICKED);

			return 0;
		}

		static int _handle_reply_command(t_connection * c, char const *text) {
			unsigned int i;
			char const * dest;

			if (!(dest = conn_get_lastsender(c))) {
				message_send_text(c, message_type_error, c, "No one messaged you, use /m instead");
				return 0;
			}

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);

			if (text[i] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /reply [message] (no have alias)");
				message_send_text(c, message_type_info, c, "** For replies to the last player who whispered you with message.");
				return 0;
			}
			do_whisper(c, dest, &text[i]);
			return 0;
		}


		static int _handle_kill_command(t_connection * c, char const *text) {
			unsigned int	i, j;
			t_connection *	user;
			char		usrnick[MAX_USERNAME_LEN];

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++)
			if (j<sizeof(usrnick)-1) usrnick[j++] = text[i];
			usrnick[j] = '\0';
			for (; text[i] == ' '; i++);

			if (usrnick[0] == '\0' || (usrnick[0] == '#' && (usrnick[1] < '0' || usrnick[1] > '9'))) {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /kill [username] [socket] [min] (no have alias)");
				message_send_text(c, message_type_info, c, "** For replies to the last player who whispered you with message.");
				return 0;
			}

			if (usrnick[0] == '#') {
				if (!(user = connlist_find_connection_by_socket(std::atoi(usrnick + 1)))) {
					message_send_text(c, message_type_info, c, "That user does not exist.");
					return 0;
				}
			}
			else {
				if (!(user = connlist_find_connection_by_accountname(usrnick))) {
					message_send_text(c, message_type_error, c, "That user is not logged in?");
					return 0;
				}
			}

			if (text[i] != '\0' && ipbanlist_add(c, addr_num_to_ip_str(conn_get_addr(user)), ipbanlist_str_to_time_t(c, &text[i])) == 0) {
				ipbanlist_save(prefs_get_ipbanfile());
				message_send_text(user, message_type_info, user, "Connection closed by admin and banned your ip.");
			}
			else
				message_send_text(user, message_type_info, user, "Connection closed by admin.");
			conn_set_state(user, conn_state_destroy);

			message_send_text(c, message_type_info, c, "Operation successful.");
			return 0;
		}

		static int _handle_killsession_command(t_connection * c, char const *text) {
			unsigned int	i, j;
			t_connection *	user;
			char		session[16];

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++)
			if (j<sizeof(session)-1) session[j++] = text[i];
			session[j] = '\0';
			for (; text[i] == ' '; i++);

			if (session[0] == '\0') {
				message_send_text(c, message_type_info, c, "usage: /killsession <session> [min]");
				return 0;
			}
			if (!std::isxdigit((int)session[0])) {
				message_send_text(c, message_type_error, c, "That is not a valid session.");
				return 0;
			}
			if (!(user = connlist_find_connection_by_sessionkey((unsigned int)std::strtoul(session, NULL, 16)))) {
				message_send_text(c, message_type_error, c, "That session does not exist.");
				return 0;
			}
			if (text[i] != '\0' && ipbanlist_add(c, addr_num_to_ip_str(conn_get_addr(user)), ipbanlist_str_to_time_t(c, &text[i])) == 0) {
				ipbanlist_save(prefs_get_ipbanfile());
				message_send_text(user, message_type_info, user, "Connection closed by admin and banned your ip's.");
			}
			else
				message_send_text(user, message_type_info, user, "Connection closed by admin.");
			conn_set_state(user, conn_state_destroy);
			return 0;
		}

		static int _handle_serverban_command(t_connection *c, char const *text) {
			char dest[MAX_USERNAME_LEN];
			t_connection * dest_c;
			unsigned int i, j;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++)
			if (j<sizeof(dest)-1) dest[j++] = text[i];
			dest[j] = '\0';
			for (; text[i] == ' '; i++);

			if (dest[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /serverban [username] (no have alias)");
				message_send_text(c, message_type_info, c, "** For bans player by IP and lock his account.");
				return 0;
			}

			if (!(dest_c = connlist_find_connection_by_accountname(dest))) {
				message_send_text(c, message_type_error, c, "That user is not logged on.");
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "Banning User %.64s who is using IP %.64s", conn_get_username(dest_c), addr_num_to_ip_str(conn_get_game_addr(dest_c)));
			message_send_text(c, message_type_info, c, msgtemp);
			message_send_text(c, message_type_info, c, "Users Account is also LOCKED! Only a Admin can Unlock it!");
			snprintf(msgtemp, sizeof(msgtemp), "/ipban a %.64s", addr_num_to_ip_str(conn_get_game_addr(dest_c)));
			handle_ipban_command(c, msgtemp);
			account_set_auth_lock(conn_get_account(dest_c), 1);

			snprintf(msgtemp, sizeof(msgtemp), "You have been banned by Admin: %.64s", conn_get_username(c));
			message_send_text(dest_c, message_type_error, dest_c, msgtemp);
			message_send_text(dest_c, message_type_error, dest_c, "Your account is also LOCKED! Only a admin can UNLOCK it!");
			conn_set_state(dest_c, conn_state_destroy);
			return 0;
		}

		static int _handle_channels_command(t_connection * c, char const *text) {
			unsigned int      i;
			t_elem const *    curr;
			t_channel const * channel;
			t_clienttag       clienttag;
			t_connection const * conn;
			t_account * acc;
			char const * name;
			int first;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);

			if (text[i] == '\0') { clienttag = conn_get_clienttag(c); }
			else if (std::strcmp(&text[i], "all") == 0) { clienttag = conn_get_clienttag(c); }
			else { clienttag = conn_get_clienttag(c); }

			message_send_text(c, message_type_error, c, "--CHANNEL -----");
			LIST_TRAVERSE_CONST(channellist(), curr) {
				channel = (t_channel*)elem_get_data(curr);
				if ((!(channel_get_flags(channel) & channel_flags_clan)) && (!clienttag || !prefs_get_hide_temp_channels() || channel_get_permanent(channel)) &&
					(!clienttag || !channel_get_clienttag(channel) || channel_get_clienttag(channel) == clienttag) &&
					((channel_get_max(channel) != 0) || ((channel_get_max(channel) == 0 && account_is_operator_or_admin(conn_get_account(c), NULL)))) &&
					(!(channel_get_flags(channel) & channel_flags_thevoid))) {
					snprintf(msgtemp, sizeof(msgtemp), "[*] %s - ",
						channel_get_name(channel),
						channel_get_length(channel));

					first = 1;
					for (conn = channel_get_first(channel); conn; conn = channel_get_next()) {
						acc = conn_get_account(conn);
						if (account_is_operator_or_admin(acc, channel_get_name(channel)) || channel_conn_is_tmpOP(channel, account_get_conn(acc))) {
							name = conn_get_loggeduser(conn);
							if (std::strlen(msgtemp) + std::strlen(name) + 6 >= MAX_MESSAGE_LEN) break;
							if (!first) std::strcat(msgtemp, " ,");
							std::strcat(msgtemp, name);
							if (account_get_auth_admin(acc, NULL) == 1) std::strcat(msgtemp, " (A)");
							else if (account_get_auth_operator(acc, NULL) == 1) std::strcat(msgtemp, " (O)");
							first = 0;
						}
					}
					message_send_text(c, message_type_info, c, msgtemp);
				}
			}
			return 0;
		}

		static int _handle_ipscan_command(t_connection * c, char const * text) {
			text = skip_command(text);
			t_account * account;
			t_connection * conn;
			char const * ip;

			if (text[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /ipscan [username or ip-address] (no have alias)");
				message_send_text(c, message_type_info, c, "** For finds all currently logged in users with the given username or IP-address.");
				return 0;
			}

			if (account = accountlist_find_account(text)) {
				conn = account_get_conn(account);
				if (conn) {
					ip = addr_num_to_ip_str(conn_get_addr(conn));
					snprintf(msgtemp, sizeof(msgtemp), "Scanning online users for IP %s!", ip);
					message_send_text(c, message_type_error, c, msgtemp);
				}
				else {
					message_send_text(c, message_type_info, c, "Warning: that user is not online, using last known address");
					if (!(ip = account_get_ll_ip(account))) {
						message_send_text(c, message_type_error, c, "Sorry, no address could be retrieved");
						return 0;
					}
				}
			}
			else {
				ip = text;
			}

			t_elem const * curr;
			int count = 0;
			LIST_TRAVERSE_CONST(connlist(), curr) {
				conn = (t_connection *)elem_get_data(curr);
				if (!conn) {
					continue;
				}

				if (std::strcmp(ip, addr_num_to_ip_str(conn_get_addr(conn))) == 0) {
					snprintf(msgtemp, sizeof(msgtemp), "[*] %s", conn_get_loggeduser(conn));
					message_send_text(c, message_type_info, c, msgtemp);
					count++;
				}
			}

			if (count == 0) {
				message_send_text(c, message_type_error, c, "There are no online users with that address");
			}

			return 0;
		}

		static int _handle_friends_command(t_connection * c, char const * text) {
			int i;
			t_account *my_acc = conn_get_account(c);
			text = skip_command(text);;

			if (strstart(text, "add") == 0 || strstart(text, "a") == 0) {
				char msgtemp[MAX_MESSAGE_LEN];
				t_packet 	* rpacket;
				t_connection 	* dest_c;
				t_account    	* friend_acc;
				t_server_friendslistreply_status status;
				t_game * game;
				t_channel * channel;
				char stat;
				t_list * flist;
				t_friend * fr;

				text = skip_command(text);
				if (text[0] == '\0') {
					message_send_text(c, message_type_info, c, "--------------------------------------------------------");
					message_send_text(c, message_type_error, c, "Usage: /f add [username] (alias: a)");
					message_send_text(c, message_type_info, c, "** For adds username to your friends list.");
					return 0;
				}

				if (!(friend_acc = accountlist_find_account(text))) {
					message_send_text(c, message_type_info, c, "That user does not exist.");
					return 0;
				}

				switch (account_add_friend(my_acc, friend_acc)) {
				case -1:
					message_send_text(c, message_type_error, c, "Server error.");
					return 0;
				case -2:
					message_send_text(c, message_type_info, c, "You can't add yourself to your friends list.");
					return 0;
				case -3:
					snprintf(msgtemp, sizeof(msgtemp), "You can only have a maximum of %d friends.", prefs_get_max_friends());
					message_send_text(c, message_type_info, c, msgtemp);
					return 0;
				case -4:
					snprintf(msgtemp, sizeof(msgtemp), "%.64s is already on your friends list!", text);
					message_send_text(c, message_type_info, c, msgtemp);
					return 0;
				}

				snprintf(msgtemp, sizeof(msgtemp), "Added %.64s to your friends list.", text);
				message_send_text(c, message_type_info, c, msgtemp);
				dest_c = connlist_find_connection_by_account(friend_acc);
				if (dest_c != NULL) {
					snprintf(msgtemp, sizeof(msgtemp), "%.64s added you to his/her friends list.", conn_get_username(c));
					message_send_text(dest_c, message_type_info, dest_c, msgtemp);
				}

				if ((conn_get_class(c) != conn_class_bnet) || (!(rpacket = packet_create(packet_class_bnet))))
					return 0;

				packet_set_size(rpacket, sizeof(t_server_friendadd_ack));
				packet_set_type(rpacket, SERVER_FRIENDADD_ACK);
				packet_append_string(rpacket, account_get_name(friend_acc));

				game = NULL;
				channel = NULL;

				if (!(dest_c)) {
					bn_byte_set(&status.location, FRIENDSTATUS_OFFLINE);
					bn_byte_set(&status.status, 0);
					bn_int_set(&status.clienttag, 0);
				}
				else {
					bn_int_set(&status.clienttag, conn_get_clienttag(dest_c));
					stat = 0;
					flist = account_get_friends(my_acc);
					fr = friendlist_find_account(flist, friend_acc);
					if ((friend_get_mutual(fr)))    stat |= FRIEND_TYPE_MUTUAL;
					if ((conn_get_dndstr(dest_c)))  stat |= FRIEND_TYPE_DND;
					if ((conn_get_awaystr(dest_c))) stat |= FRIEND_TYPE_AWAY;
					bn_byte_set(&status.status, stat);
					if ((game = conn_get_game(dest_c))) {
						if (game_get_flag(game) != game_flag_private)
							bn_byte_set(&status.location, FRIENDSTATUS_PUBLIC_GAME);
						else
							bn_byte_set(&status.location, FRIENDSTATUS_PRIVATE_GAME);
					}
					else if ((channel = conn_get_channel(dest_c))) {
						bn_byte_set(&status.location, FRIENDSTATUS_CHAT);
					}
					else {
						bn_byte_set(&status.location, FRIENDSTATUS_ONLINE);
					}
				}

				packet_append_data(rpacket, &status, sizeof(status));
				if (game) packet_append_string(rpacket, game_get_name(game));
				else if (channel) packet_append_string(rpacket, channel_get_name(channel));
				else packet_append_string(rpacket, "");

				conn_push_outqueue(c, rpacket);
				packet_del_ref(rpacket);
			}

			else if (strstart(text, "msg") == 0 || strstart(text, "w") == 0 || strstart(text, "whisper") == 0 || strstart(text, "m") == 0) {
				char const *msg;
				int cnt = 0;
				t_connection * dest_c;
				t_elem  * curr;
				t_friend * fr;
				t_list  * flist;

				msg = skip_command(text);
				if (msg[0] == '\0') {
					message_send_text(c, message_type_info, c, "Did not message any friends. Type some text next time.");
					return 0;
				}

				flist = account_get_friends(my_acc);
				if (flist == NULL)
					return -1;

				LIST_TRAVERSE(flist, curr) {
					if (!(fr = (t_friend*)elem_get_data(curr))) {
						eventlog(eventlog_level_error, __FUNCTION__, "found NULL entry in list");
						continue;
					}
					if (friend_get_mutual(fr)) {
						dest_c = connlist_find_connection_by_account(friend_get_account(fr));
						if (!dest_c) continue;
						message_send_text(dest_c, message_type_whisper, c, msg);
						cnt++;
					}
				}
				if (cnt)
					message_send_text(c, message_type_friendwhisperack, c, msg);
				else
					message_send_text(c, message_type_info, c, "All your friends are offline.");
			}

			else if (strstart(text, "r") == 0 || strstart(text, "remove") == 0 || strstart(text, "del") == 0 || strstart(text, "delete") == 0) {
				int num;
				char msgtemp[MAX_MESSAGE_LEN];
				t_packet * rpacket;

				text = skip_command(text);
				if (text[0] == '\0') {
					message_send_text(c, message_type_info, c, "--------------------------------------------------------");
					message_send_text(c, message_type_error, c, "Usage: /f remove [username] (alias: r del delete)");
					message_send_text(c, message_type_info, c, "** For removes username from your friends list.");
					return 0;
				}

				switch ((num = account_remove_friend2(my_acc, text))) {
				case -1: return -1;
				case -2:
					snprintf(msgtemp, sizeof(msgtemp), "%.64s was not found on your friends list.", text);
					message_send_text(c, message_type_info, c, msgtemp);
					return 0;
				default:
					snprintf(msgtemp, sizeof(msgtemp), "Removed %.64s from your friends list.", text);
					message_send_text(c, message_type_info, c, msgtemp);

					if ((conn_get_class(c) != conn_class_bnet) || (!(rpacket = packet_create(packet_class_bnet))))
						return 0;

					packet_set_size(rpacket, sizeof(t_server_frienddel_ack));
					packet_set_type(rpacket, SERVER_FRIENDDEL_ACK);
					bn_byte_set(&rpacket->u.server_frienddel_ack.friendnum, num);

					conn_push_outqueue(c, rpacket);
					packet_del_ref(rpacket);

					return 0;
				}
			}
			else if (strstart(text, "p") == 0 || strstart(text, "promote") == 0) {
				int num;
				int n;
				char msgtemp[MAX_MESSAGE_LEN];
				char const * dest_name;
				t_packet * rpacket;
				t_list * flist;
				t_friend * fr;
				t_account * dest_acc;
				unsigned int dest_uid;

				text = skip_command(text);
				if (text[0] == '\0') {
					message_send_text(c, message_type_info, c, "--------------------------------------------------------");
					message_send_text(c, message_type_error, c, "Usage: /f promote [username] (alias: p)");
					message_send_text(c, message_type_info, c, "** For promotes username one line up your friends list.");
					return 0;
				}

				num = account_get_friendcount(my_acc);
				flist = account_get_friends(my_acc);
				for (n = 1; n<num; n++)
				if ((dest_uid = account_get_friend(my_acc, n)) && (fr = friendlist_find_uid(flist, dest_uid)) &&
					(dest_acc = friend_get_account(fr)) && (dest_name = account_get_name(dest_acc)) && (strcasecmp(dest_name, text) == 0)) {
					account_set_friend(my_acc, n, account_get_friend(my_acc, n - 1));
					account_set_friend(my_acc, n - 1, dest_uid);
					snprintf(msgtemp, sizeof(msgtemp), "Premoted %.64s in your friends list.", dest_name);
					message_send_text(c, message_type_info, c, msgtemp);

					if ((conn_get_class(c) != conn_class_bnet) || (!(rpacket = packet_create(packet_class_bnet))))
						return 0;

					packet_set_size(rpacket, sizeof(t_server_friendmove_ack));
					packet_set_type(rpacket, SERVER_FRIENDMOVE_ACK);
					bn_byte_set(&rpacket->u.server_friendmove_ack.pos1, n - 1);
					bn_byte_set(&rpacket->u.server_friendmove_ack.pos2, n);

					conn_push_outqueue(c, rpacket);
					packet_del_ref(rpacket);
					return 0;
				}
			}

			else if (strstart(text, "d") == 0 || strstart(text, "demote") == 0) {
				int num;
				int n;
				char msgtemp[MAX_MESSAGE_LEN];
				char const * dest_name;
				t_packet * rpacket;
				t_list * flist;
				t_friend * fr;
				t_account * dest_acc;
				unsigned int dest_uid;

				text = skip_command(text);
				if (text[0] == '\0') {
					message_send_text(c, message_type_info, c, "--------------------------------------------------------");
					message_send_text(c, message_type_error, c, "Usage: /f demote [username] (alias: d)");
					message_send_text(c, message_type_info, c, "** For demotes username one line down your friends list");
					return 0;
				}

				num = account_get_friendcount(my_acc);
				flist = account_get_friends(my_acc);
				for (n = 0; n<num - 1; n++)
				if ((dest_uid = account_get_friend(my_acc, n)) && (fr = friendlist_find_uid(flist, dest_uid)) &&
					(dest_acc = friend_get_account(fr)) && (dest_name = account_get_name(dest_acc)) && (strcasecmp(dest_name, text) == 0)) {
					account_set_friend(my_acc, n, account_get_friend(my_acc, n + 1));
					account_set_friend(my_acc, n + 1, dest_uid);
					snprintf(msgtemp, sizeof(msgtemp), "Premoted %.64s in your friends list.", dest_name);
					message_send_text(c, message_type_info, c, msgtemp);

					if ((conn_get_class(c) != conn_class_bnet) || (!(rpacket = packet_create(packet_class_bnet))))
						return 0;

					packet_set_size(rpacket, sizeof(t_server_friendmove_ack));
					packet_set_type(rpacket, SERVER_FRIENDMOVE_ACK);
					bn_byte_set(&rpacket->u.server_friendmove_ack.pos1, n);
					bn_byte_set(&rpacket->u.server_friendmove_ack.pos2, n + 1);

					conn_push_outqueue(c, rpacket);
					packet_del_ref(rpacket);
					return 0;
				}
			}

			else if (strstart(text, "list") == 0 || strstart(text, "l") == 0) {
				char const * frienduid;
				char status[128];
				char software[64];
				char msgtemp[MAX_MESSAGE_LEN];
				t_connection * dest_c;
				t_account * friend_acc;
				t_game const * game;
				t_channel const * channel;
				t_friend * fr;
				t_list  * flist;
				int num;
				unsigned int uid;

				message_send_text(c, message_type_error, c, "-- FRIENDS -----");
				num = account_get_friendcount(my_acc);

				flist = account_get_friends(my_acc);
				if (flist != NULL) {
					for (i = 0; i<num; i++) {
						if ((!(uid = account_get_friend(my_acc, i))) || (!(fr = friendlist_find_uid(flist, uid)))) {
							eventlog(eventlog_level_error, __FUNCTION__, "friend uid in list");
							continue;
						}
						software[0] = '\0';
						friend_acc = friend_get_account(fr);

						if (!(dest_c = connlist_find_connection_by_account(friend_acc)))
							std::sprintf(status, ", offline");
						else {
							std::sprintf(software, " using %s", clienttag_get_title(conn_get_clienttag(dest_c)));

							if (friend_get_mutual(fr)) {
								if ((game = conn_get_game(dest_c)))
									std::sprintf(status, ", in game \"%.64s\"", game_get_name(game));
								else if ((channel = conn_get_channel(dest_c))) {
									if (strcasecmp(channel_get_name(channel), "Arranged Teams") == 0)
										std::sprintf(status, ", in game AT Preparation");
									else
										std::sprintf(status, ", in channel \"%.64s\",", channel_get_name(channel));
								}
								else
									std::sprintf(status, ", is in AT Preparation");
							}
							else {
								if ((game = conn_get_game(dest_c)))
									std::sprintf(status, ", is in a game");
								else if ((channel = conn_get_channel(dest_c)))
									std::sprintf(status, ", is in a chat channel");
								else
									std::sprintf(status, ", is in AT Preparation");
							}
						}

						frienduid = account_get_name(friend_acc);
						if (software[0]) snprintf(msgtemp, sizeof(msgtemp), "%d: %s%.16s%.128s, %.64s", i + 1, friend_get_mutual(fr) ? "*" : " ", frienduid, status, software);
						else snprintf(msgtemp, sizeof(msgtemp), "%d: %.16s%.128s", i + 1, frienduid, status);
						message_send_text(c, message_type_info, c, msgtemp);
					}
				}
			}
			else {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /f add [username] (alias: a)");
				message_send_text(c, message_type_info, c, "** For adds username to your friends list.");
				message_send_text(c, message_type_error, c, "Usage: /f del [username] (alias: r remove delete)");
				message_send_text(c, message_type_info, c, "** For removes username from your friends list.");
				message_send_text(c, message_type_error, c, "Usage: /f promote [username] (alias: p)");
				message_send_text(c, message_type_info, c, "** For promotes username one line up your friends list.");
				message_send_text(c, message_type_error, c, "Usage: /f demote [username] (alias: d)");
				message_send_text(c, message_type_info, c, "** For demotes username one line down your friends list");
				message_send_text(c, message_type_error, c, "Usage: /f list (alias: l)");
				message_send_text(c, message_type_info, c, "** For displays your friends list.");
				message_send_text(c, message_type_error, c, "Usage: /f msg (alias: w m whisper)");
				message_send_text(c, message_type_info, c, "** For whisper message to all of your online friends.");
			}
			return 0;
		}

		static int _handle_finger_command(t_connection * c, char const *text)
		{
			char           dest[MAX_USERNAME_LEN];
			unsigned int   i, j;
			t_account *    account;
			t_connection * conn;
			char const *   ip;
			char *         tok;
			t_clanmember * clanmemb;

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++); /* skip command */
			for (; text[i] == ' '; i++);
			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++) /* get dest */
			if (j<sizeof(dest)-1) dest[j++] = text[i];
			dest[j] = '\0';
			for (; text[i] == ' '; i++);

			if (dest[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /finger [username] (alias: /ignore)");
				message_send_text(c, message_type_info, c, "** For displays detailed information about player.");
				return 0;
			}

			if (!(account = accountlist_find_account(dest))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return 0;
			}

			message_send_text(c, message_type_error, c, "--------------------------------------------------------");
			snprintf(msgtemp, sizeof(msgtemp), "[*] Username: %s", account_get_name(account));
			message_send_text(c, message_type_error, c, msgtemp);
			snprintf(msgtemp, sizeof(msgtemp), "[*] ID: "UID_FORMAT"", account_get_uid(account));
			message_send_text(c, message_type_info, c, msgtemp);
			snprintf(msgtemp, sizeof(msgtemp), "[*] User Class: %s", account_get_class(account));
			message_send_text(c, message_type_info, c, msgtemp);

			if ((clanmemb = account_get_clanmember(account))) {
				t_clan *	 clan;
				char	 status;

				if ((clan = clanmember_get_clan(clanmemb))) {
					snprintf(msgtemp, sizeof(msgtemp), "[*] Clan: %s", clan_get_name(clan));
					message_send_text(c, message_type_info, c, msgtemp);
				}
			}

			snprintf(msgtemp, sizeof(msgtemp), "[*] Total Coin: %s", account_get_coin(account));
			message_send_text(c, message_type_info, c, msgtemp);

			if ((conn = connlist_find_connection_by_accountname(dest))) {
				message_send_text(c, message_type_info, c, " ");
				message_send_text(c, message_type_error, c, "--------------------------------------------------------");
				snprintf(msgtemp, sizeof(msgtemp), "[*] Client: %s", clienttag_get_title(conn_get_clienttag(conn)));
				message_send_text(c, message_type_info, c, msgtemp);
				snprintf(msgtemp, sizeof(msgtemp), "[*] Patch Version: %s", conn_get_clientver(conn));
				message_send_text(c, message_type_info, c, msgtemp);
			}

			message_send_text(c, message_type_info, c, " ");
			message_send_text(c, message_type_error, c, "--------------------------------------------------------");
			snprintf(msgtemp, sizeof(msgtemp), "[*] User Level: %s", account_get_level(account));
			message_send_text(c, message_type_info, c, msgtemp);
			snprintf(msgtemp, sizeof(msgtemp), "[*] Last Games Played: %s", account_get_lastgameplayed(account));
			message_send_text(c, message_type_info, c, msgtemp);

			ip = "";
			std::time_t      then;
			struct std::tm * tmthen;
			then = account_get_ll_time(account);
			tmthen = std::localtime(&then);

			if (!(conn)) {
				if (tmthen)
					std::strftime(msgtemp, sizeof(msgtemp), "Last login %a, %d %b %Y %H:%M", tmthen);
				else
					std::strcpy(msgtemp, "Last login ? * ");
			}
			else {
				if (tmthen)
					std::strftime(msgtemp, sizeof(msgtemp), "On since %a, %d %b %Y %H:%M", tmthen);
				else
					std::strcpy(msgtemp, "On since ? * ");
			}

			std::strncat(msgtemp, ip, 32);
			message_send_text(c, message_type_info, c, "--------------------------------------------------------");
			message_send_text(c, message_type_info, c, msgtemp);

			if (conn) {
				snprintf(msgtemp, sizeof(msgtemp), "AFK : %.128s", seconds_to_timestr(conn_get_idletime(conn)));
				message_send_text(c, message_type_info, c, msgtemp);
			}

			return 0;
		}

		static int _handle_move_command(t_connection * c, char const *text) {
			t_channel * channel;
			unsigned int i, j;
			char  arg1[256];
			char  arg2[256];
			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);

			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++)
			if (j<sizeof(arg1)-1) arg1[j++] = text[i];
			arg1[j] = '\0';

			for (; text[i] == ' '; i++);
			for (j = 0; text[i] != '\0'; i++)
			if (j<sizeof(arg2)-1) arg2[j++] = text[i];
			arg2[j] = '\0';
			t_connection * rev_c = connlist_find_connection_by_accountname(arg1);

			if (arg2[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /move [username] [channel] (alias: /ignore)");
				message_send_text(c, message_type_info, c, "** For moving player to target channel.");
				return 0;
			}

			if (!conn_get_game(rev_c)) {
				if (strcasecmp(text, "Arranged Teams") == 0) {
					message_send_text(c, message_type_error, c, "Channel Arranged Teams is a RESTRICTED Channel!");
					return 0;
				}

				if (!(std::strlen(arg2) < MAX_CHANNELNAME_LEN)) {
					snprintf(msgtemp, sizeof(msgtemp), "max channel name length exceeded (max %d symbols)", MAX_CHANNELNAME_LEN - 1);
					message_send_text(c, message_type_error, c, msgtemp);
					return 0;
				}

				if ((channel = conn_get_channel(c)) && (strcasecmp(channel_get_name(channel), text) == 0))
					return 0;

				if (conn_set_channel(rev_c, arg2)<0)
					conn_set_channel(rev_c, CHANNEL_NAME_BANNED);
				if ((conn_get_clienttag(rev_c) == CLIENTTAG_WARCRAFT3_UINT) || (conn_get_clienttag(rev_c) == CLIENTTAG_WAR3XP_UINT))
					conn_update_w3_playerinfo(rev_c);
				command_set_flags(rev_c);
			}
			else
				message_send_text(c, message_type_error, c, "Command disabled while inside a game.");

			return 0;
		}

		static int _handle_seticon_command(t_connection * c, char const *text) {
			t_account *    account;
			char *    command;
			char *    username;
			char *  icon;
			char     t[MAX_MESSAGE_LEN];
			unsigned int i, j;
			char    arg1[256];
			char    arg2[256];
			char    arg3[256];

			std::strncpy(t, text, MAX_MESSAGE_LEN - 1);
			for (i = 0; t[i] != ' ' && t[i] != '\0'; i++);
			for (; t[i] == ' '; i++);
			for (j = 0; t[i] != ' ' && t[i] != '\0'; i++)
			if (j<sizeof(arg1)-1) arg1[j++] = t[i];
			arg1[j] = '\0';

			for (; t[i] == ' '; i++);
			for (j = 0; t[i] != ' ' && t[i] != '\0'; i++)
			if (j<sizeof(arg2)-1) arg2[j++] = t[i];
			arg2[j] = '\0';

			for (; t[i] == ' '; i++);
			for (j = 0; t[i] != '\0'; i++)
			if (j<sizeof(arg3)-1) arg3[j++] = t[i];
			arg3[j] = '\0';

			command = arg1;
			username = arg2;
			icon = arg3;

			for (i = 0; i<std::strlen(icon); i++)
			if (std::isupper((int)icon[i])) icon[i] = std::tolower((int)icon[i]);

			if (arg1[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /seticon [command] [username] [icon code] (no have alias)");
				message_send_text(c, message_type_info, c, "** For setting custom icon add/del from command.");
				message_send_text(c, message_type_error, c, "Usage: /seticon help (alias: h)");
				message_send_text(c, message_type_info, c, "** For help command seticon.");
				return 0;
			}

			if (!std::strcmp(command, "help") || !std::strcmp(command, "h")) {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /seticon add [username] [icon code] (alias: a)");
				message_send_text(c, message_type_info, c, "** For adds custom icon to player.");
				message_send_text(c, message_type_error, c, "Usage: /seticon del [username] [icon code] (alias: d)");
				message_send_text(c, message_type_info, c, "** For removes custom icon from player.");
				message_send_text(c, message_type_error, c, "Type: /seticon list [username] (alias: l)");
				message_send_text(c, message_type_info, c, "** For display all custom icons.");
				return 0;
			}

			if (!std::strcmp(command, "list") || !std::strcmp(command, "l")) {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "** Random Race :");
				message_send_text(c, message_type_info, c, "[*] Green Dragon Whelp: greendragon");
				message_send_text(c, message_type_info, c, "[*] Blue Dragon: bluedragon");
				message_send_text(c, message_type_info, c, "[*] Red Dragon: reddragon");
				message_send_text(c, message_type_info, c, "[*] Darkwing: darkwing");

				message_send_text(c, message_type_error, c, "** Human Race :");
				message_send_text(c, message_type_info, c, "[*] Peasant: peasant");
				message_send_text(c, message_type_info, c, "[*] Footman: footman");
				message_send_text(c, message_type_info, c, "[*] Knight: knight");
				message_send_text(c, message_type_info, c, "[*] Archmage: archmage");
				message_send_text(c, message_type_info, c, "[*] Medivh: medivh");

				message_send_text(c, message_type_error, c, "** Orc Race :");
				message_send_text(c, message_type_info, c, "[*] Peon: peon");
				message_send_text(c, message_type_info, c, "[*] Grunt: grunt");
				message_send_text(c, message_type_info, c, "[*] Tauren: tauren");
				message_send_text(c, message_type_info, c, "[*] Far Seer: farseer");
				message_send_text(c, message_type_info, c, "[*] Thrall: thrall");

				message_send_text(c, message_type_error, c, "** Undead Race :");
				message_send_text(c, message_type_info, c, "[*] Acolyle: acolyle");
				message_send_text(c, message_type_info, c, "[*] Ghoul: ghoul");
				message_send_text(c, message_type_info, c, "[*] Abomination: abomination");
				message_send_text(c, message_type_info, c, "[*] Lich: lich");
				message_send_text(c, message_type_info, c, "[*] Tichondrius: tichondrius");

				message_send_text(c, message_type_error, c, "** Nightelves Race :");
				message_send_text(c, message_type_info, c, "[*] Wisp: wisp");
				message_send_text(c, message_type_info, c, "[*] Archer: archer");
				message_send_text(c, message_type_info, c, "[*] Druid of the Claw: druid");
				message_send_text(c, message_type_info, c, "[*] Priestess of the Moon: priestess");
				message_send_text(c, message_type_info, c, "[*] Furion Stormrage: furion");
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				return 0;
			}

			if (arg1[0] == '\0' || arg2[0] == '\0' || arg3[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /seticon [command] [username] [icon code] (no have alias)");
				message_send_text(c, message_type_info, c, "** For setting custom icon add/del from command.");
				message_send_text(c, message_type_error, c, "Usage: /seticon help (alias: h)");
				message_send_text(c, message_type_info, c, "** For help command seticon.");
				return 0;
			}

			if (!(account = accountlist_find_account(username))) {
				message_send_text(c, message_type_info, c, "That user does not exist.");
				return 0;
			}

			if (!std::strcmp(icon, "greendragon") || !std::strcmp(icon, "bluedragon") || !std::strcmp(icon, "reddragon") || !std::strcmp(icon, "darkwing")
				|| !std::strcmp(icon, "peasant") || !std::strcmp(icon, "footman") || !std::strcmp(icon, "knight") || !std::strcmp(icon, "archmage") || !std::strcmp(icon, "medivh")
				|| !std::strcmp(icon, "peon") || !std::strcmp(icon, "grunt") || !std::strcmp(icon, "tauren") || !std::strcmp(icon, "farseer") || !std::strcmp(icon, "thrall")
				|| !std::strcmp(icon, "acolyle") || !std::strcmp(icon, "ghoul") || !std::strcmp(icon, "abomination") || !std::strcmp(icon, "lich") || !std::strcmp(icon, "tichondrius")
				|| !std::strcmp(icon, "wisp") || !std::strcmp(icon, "archer") || !std::strcmp(icon, "druid") || !std::strcmp(icon, "priestess") || !std::strcmp(icon, "furion")) { /*Do nothing.*/
			}
			else {
				eventlog(eventlog_level_warn, __FUNCTION__, "unknown icon: %x", text);
				snprintf(msgtemp, sizeof(msgtemp), "No such icon, unable to set!");
				message_send_text(c, message_type_error, c, msgtemp);
				return 0;
			}

			if (!std::strcmp(command, "add") || !std::strcmp(command, "a")) {
				account_set_auth_icon(account, icon, 1);
				snprintf(msgtemp, sizeof(msgtemp), "%.128s is setted to the requested account.", icon);
				message_send_text(c, message_type_info, c, msgtemp);
				return 0;
			}

			if (!std::strcmp(command, "del") || !std::strcmp(command, "d")) {
				account_set_auth_icon(account, icon, 0);
				snprintf(msgtemp, sizeof(msgtemp), "%.128s is removed from the requested account.", icon);
				message_send_text(c, message_type_info, c, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "got unknown command: %.128s", command);
			message_send_text(c, message_type_error, c, msgtemp);
			return 0;

		}

		static int _handle_icon_command(t_connection * c, char const *text) {
			t_account *   account;
			t_clienttag     clienttag;
			char const     *user_icon;
			unsigned int i, j;
			char    arg1[256];
			char *    icon;

			account = conn_get_account(c);
			clienttag = conn_get_clienttag(c);
			user_icon = "XXXX";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);

			for (j = 0; text[i] != ' ' && text[i] != '\0'; i++)
			if (j<sizeof(arg1)-1) arg1[j++] = text[i];
			arg1[j] = '\0';

			icon = arg1;
			if (arg1[0] == '\0') {
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				message_send_text(c, message_type_error, c, "Usage: /icon [icon code] (no have alias) - for change your custom icons.");
				if (account_get_auth_icon(account, "greendragon") == 1) 	message_send_text(c, message_type_info, c, "[*] Green Dragon (greendragon)");
				if (account_get_auth_icon(account, "bluedragon") == 1) 		message_send_text(c, message_type_info, c, "[*] Blue Dragon (bluedragon)");
				if (account_get_auth_icon(account, "reddragon") == 1) 		message_send_text(c, message_type_info, c, "[*] Red Dragon (reddragon)");
				if (account_get_auth_icon(account, "darkwing") == 1) 		message_send_text(c, message_type_info, c, "[*] Darkwing (darkwing)");
				if (account_get_auth_icon(account, "peasant") == 1) 		message_send_text(c, message_type_info, c, "[*] Peasant (peasant)");
				if (account_get_auth_icon(account, "footman") == 1) 		message_send_text(c, message_type_info, c, "[*] Footman (footman)");
				if (account_get_auth_icon(account, "knight") == 1) 			message_send_text(c, message_type_info, c, "[*] Knight (knight)");
				if (account_get_auth_icon(account, "archmage") == 1) 		message_send_text(c, message_type_info, c, "[*] Archmage (archmage)");
				if (account_get_auth_icon(account, "medivh") == 1) 			message_send_text(c, message_type_info, c, "[*] Medivh (medivh)");
				if (account_get_auth_icon(account, "peon") == 1) 			message_send_text(c, message_type_info, c, "[*] Peon (peon)");
				if (account_get_auth_icon(account, "grunt") == 1) 			message_send_text(c, message_type_info, c, "[*] Grunt (grunt)");
				if (account_get_auth_icon(account, "tauren") == 1) 			message_send_text(c, message_type_info, c, "[*] Tauren (tauren)");
				if (account_get_auth_icon(account, "farseer") == 1) 		message_send_text(c, message_type_info, c, "[*] Far Seer (farseer)");
				if (account_get_auth_icon(account, "thrall") == 1) 			message_send_text(c, message_type_info, c, "[*] Thrall (thrall)");
				if (account_get_auth_icon(account, "acolyle") == 1) 		message_send_text(c, message_type_info, c, "[*] Acolyle (acolyle)");
				if (account_get_auth_icon(account, "ghoul") == 1) 			message_send_text(c, message_type_info, c, "[*] Ghoul (ghoul)");
				if (account_get_auth_icon(account, "abomination") == 1) 	message_send_text(c, message_type_info, c, "[*] Abomination (abomination)");
				if (account_get_auth_icon(account, "lich") == 1) 			message_send_text(c, message_type_info, c, "[*] Lich (lich)");
				if (account_get_auth_icon(account, "tichondrius") == 1) 	message_send_text(c, message_type_info, c, "[*] Tichondrius (tichondrius)");
				if (account_get_auth_icon(account, "wisp") == 1) 			message_send_text(c, message_type_info, c, "[*] Wisp (wisp)");
				if (account_get_auth_icon(account, "archer") == 1) 			message_send_text(c, message_type_info, c, "[*] Archer (archer)");
				if (account_get_auth_icon(account, "druid") == 1) 			message_send_text(c, message_type_info, c, "[*] Druid of the Claw (druid)");
				if (account_get_auth_icon(account, "priestess") == 1) 		message_send_text(c, message_type_info, c, "[*] Priestess of the Moon (priestess)");
				if (account_get_auth_icon(account, "furion") == 1) 			message_send_text(c, message_type_info, c, "[*] Furion Stormrage (furion)");
				message_send_text(c, message_type_info, c, "--------------------------------------------------------");
				return 0;
			}

			for (i = 0; i<std::strlen(icon); i++)
			if (std::isupper((int)icon[i])) icon[i] = std::tolower((int)icon[i]);

			if (!std::strcmp(icon, "greendragon"))    		user_icon = "213W";
			if (!std::strcmp(icon, "bluedragon"))    		user_icon = "313W";
			if (!std::strcmp(icon, "reddragon"))    		user_icon = "413W";
			if (!std::strcmp(icon, "darkwing"))    			user_icon = "513W";
			if (!std::strcmp(icon, "peasant"))    			user_icon = "123W";
			if (!std::strcmp(icon, "footman"))    			user_icon = "223W";
			if (!std::strcmp(icon, "knight"))    			user_icon = "323W";
			if (!std::strcmp(icon, "archmage"))    			user_icon = "423W";
			if (!std::strcmp(icon, "medivh"))    			user_icon = "523W";
			if (!std::strcmp(icon, "peon"))    				user_icon = "133W";
			if (!std::strcmp(icon, "grunt"))    			user_icon = "233W";
			if (!std::strcmp(icon, "tauren"))    			user_icon = "333W";
			if (!std::strcmp(icon, "farseer"))    			user_icon = "433W";
			if (!std::strcmp(icon, "thrall"))    			user_icon = "533W";
			if (!std::strcmp(icon, "acolyle"))    			user_icon = "143W";
			if (!std::strcmp(icon, "ghoul"))    			user_icon = "243W";
			if (!std::strcmp(icon, "abomination"))    		user_icon = "343W";
			if (!std::strcmp(icon, "lich"))    				user_icon = "443W";
			if (!std::strcmp(icon, "tichondrius"))    		user_icon = "543W";
			if (!std::strcmp(icon, "wisp"))    				user_icon = "153W";
			if (!std::strcmp(icon, "archer"))    			user_icon = "253W";
			if (!std::strcmp(icon, "druid"))    			user_icon = "353W";
			if (!std::strcmp(icon, "priestess"))    		user_icon = "453W";
			if (!std::strcmp(icon, "furion"))    			user_icon = "553W";


			if (!std::strcmp(user_icon, "XXXX")) {
				eventlog(eventlog_level_warn, __FUNCTION__, "unknown icon: %x", icon);
				snprintf(msgtemp, sizeof(msgtemp), "No such icon.");
				message_send_text(c, message_type_error, c, msgtemp);
				return 0;
			}

			if (account_get_auth_icon(account, icon) == 1) {
				account_set_user_icon(account, clienttag, user_icon);
				conn_update_w3_playerinfo(c);
				channel_rejoin(c);
			}
			else {
				snprintf(msgtemp, sizeof(msgtemp), "Sorry, something is wrong :(");
				message_send_text(c, message_type_error, c, msgtemp);
			}
			return 0;
		}

		// NEW BATTLENET FOR BOT
		static int _handle_botevent_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-event %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-event %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botrules_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-rules %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-rules %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botdonate_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-donate %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-donate %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botcoin_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-coin %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-coin %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botcreate_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-create %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-create %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botstatus_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-status %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-status %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botchatstaff_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-chat %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-chat %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botaccept_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-accept %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-accept %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botdecline_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-decline %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-decline %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botrequest_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-request %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-request %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botstaff_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-staff %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-staff %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botonline_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-online %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-online %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botlock_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-lock %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-lock %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botunlock_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-unlock %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-unlock %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botmute_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-mute %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-mute %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botunmute_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-unmute %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-unmute %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botannounce_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-announce %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-announce %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botcmd_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-cmd %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-cmd %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botadd_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-add %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-add %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		static int _handle_botremove_command(t_connection * c, char const *text) {
			unsigned int i;
			t_connection *    user;
			t_game     *    game;
			char const * dest = "Battlenet";

			for (i = 0; text[i] != ' ' && text[i] != '\0'; i++);
			for (; text[i] == ' '; i++);
			if (text[0] == '*')
				text++;

			if (text[0] == '\0') {
				snprintf(msgtemp, sizeof(msgtemp), "-remove %s", &text[i]);
				do_botchat(c, dest, msgtemp);
				return 0;
			}

			snprintf(msgtemp, sizeof(msgtemp), "-remove %s", &text[i]);
			do_botchat(c, dest, msgtemp);
			return 0;
		}

		// END BATTLENET -------------------
	}

}
