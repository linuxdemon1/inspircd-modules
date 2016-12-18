/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2012 Shawn Smith <shawn@inspircd.org>
 *   Copyright (C) 2009 Daniel De Graaf <danieldg@inspircd.org>
 *   Copyright (C) 2006-2008 Robin Burchell <robin+git@viroteck.net>
 *   Copyright (C) 2008 Pippijn van Steenhoven <pip88nl@gmail.com>
 *   Copyright (C) 2006, 2008 Craig Edwards <craigedwards@brainbox.cc>
 *   Copyright (C) 2007 Dennis Friis <peavey@inspircd.org>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* $ModDesc: Sends an snotice when it detects mass PM spam, by comparing message hashes */

#include <sstream>

#include "inspircd.h"
#include "hash.h"


class CommandBotSpam : public Command
{
public:
	bool enabled;

	CommandBotSpam(Module *m) : Command(m, "BOTSPAM", 1, 1), enabled(false)
	{
		this->syntax = "<state>";
		flags_needed = 'o';
	}

	CmdResult Handle(const std::vector<std::string> &parameters, User *user)
	{
		std::string state = parameters[0];
		std::transform(state.begin(), state.end(), state.begin(), ::toupper);
		if (state == "ON")
			enabled = true;
		else if (state == "OFF")
			enabled = false;
		else
			return CMD_FAILURE;
		user->WriteServ("NOTICE %s :Bot spam filtering %s", user->nick.c_str(), enabled ? "enabled" : "disabled");
		return CMD_SUCCESS;
	}
};


class ModuleMassPmFilter : public Module
{
	CommandBotSpam commandBotSpam;
	std::map<std::string, std::pair<int, time_t> > msgmap;
	long repeats;
	time_t watchtime;
	bool ignoreopers;
	dynamic_reference<HashProvider> Hash;
public:
	ModuleMassPmFilter() : commandBotSpam(this), Hash(this, "hash/md5")
	{
	}

	void init()
	{
		ServiceProvider *providerlist[] = {&commandBotSpam};
		ServerInstance->Modules->AddServices(providerlist, sizeof(providerlist) / sizeof(ServiceProvider *));
		Implementation eventlist[] = {I_OnUserMessage, I_OnBackgroundTimer};
		ServerInstance->Modules->Attach(eventlist, this, sizeof(eventlist) / sizeof(Implementation));
		OnRehash(NULL);
		ServerInstance->SNO->EnableSnomask('F', "BOTSPAM");
	}

	void OnRehash(User *user)
	{
		ConfigTag *tag = ServerInstance->Config->ConfValue("massmsgspam");
		repeats = tag->getInt("repeats", 10);
		watchtime = tag->getInt("watchtime", 600);
		ignoreopers = tag->getBool("ignoreopers", true);
	}

	void OnUserMessage(User *user, void *dest, int target_type, const std::string &text, char status,
					   const CUList &exempt_list)
	{
		if (!IS_LOCAL(user) || !commandBotSpam.enabled || target_type != TYPE_USER)
			return;

		if (ignoreopers && IS_OPER(user))
			return;

		const std::string &sum = Hash->sum(text);
		if (msgmap.find(sum) == msgmap.end())
			msgmap[sum] = std::pair<int, time_t>(0, 0);

		msgmap[sum].first++;
		msgmap[sum].second = time(NULL);
		if (msgmap[sum].first >= repeats)
		{
			std::stringstream sstr;
			sstr << "Mass PM flood triggered by: " << user->nick << "@" << user->host << " (limit was " << repeats
				 << " in " << watchtime << " seconds)";
			ServerInstance->SNO->WriteGlobalSno('a', sstr.str());
		}
	}

	virtual void OnBackgroundTimer(time_t curtime)
	{
		std::map<std::string, std::pair<int, time_t> >::iterator it;
		for (it = msgmap.begin(); it != msgmap.end();)
		{
			if (curtime > (it->second.second +
						   this->watchtime))  // We should remove message hashes that have been stored for longer than watchtime
			{
				ServerInstance->SNO->WriteGlobalSno('a', "BotSpam: Removing hash from msgmap");
				std::map<std::string, std::pair<int, time_t> >::iterator toErase = it; // To avoid iterator invalidation
				it++;
				msgmap.erase(it);
			}
			else
				it++;
		}
	}

	Version GetVersion()
	{
		return Version("Blocks botnet like pm spam", VF_OPTCOMMON | VF_VENDOR);
	}
};

MODULE_INIT(ModuleMassPmFilter)