@load base/bif/plugins/Zeek_TCP.events.bif


## Mining detection
module MINING;

export
{
	redef enum Log::ID += { LOG };

	option log_path = "mining";

	const MINING_REGEX: vector of pattern {/id/, /jsonrpc/, /method/, /params/, /mining/};

	redef tcp_content_deliver_all_orig = T;
	redef tcp_content_deliver_all_resp = T;

	type Info: record
	{
		id: conn_id &log;
		method: string &log &default="";
		user_agent: string &log &default="";
		coin: string &log &default="";
		wallet: string &log &default="";
		logged: bool &default=F;
	};

	type Transfer: record
	{
		method: string &default="";
		param: string &default="";
		coin: string &default="";
	};

	global miners: table[string] of Info;

	global is_mining_packet: function(contents: string): bool;
	global find_param: function(contents: string, param: pattern, delimiter: pattern): string_vec;
	global packer: function(c: connection, transfer: Transfer);
	global logger: function(uid: string);

}


function watch_dog(c: connection, contents: string)
{
	if (!is_mining_packet(contents))
	{
		return;
	}

	local transfer: Transfer;

	local methods = find_param(contents, /\"method\":\".+\"/, /\"/);
	local params = find_param(contents, /\"params\":\[.+\]/, /\[/);
	local result = find_param(contents, /\"result\":\[.+\]/, /\"/);

	transfer$coin = |result| > 0 ? result[14] : "";

	if (|methods| > 0 && |params| > 0)
	{
		transfer$method = methods[6];
		transfer$param = params[2];
	}

	packer(c, transfer);
}


function is_mining_packet(contents: string): bool
{
	local encounter: count;
	encounter = 0;

	for (regex in MINING_REGEX)
	{
		if (MINING_REGEX[regex] in contents)
		{
			encounter += 1;
		}
	}

	return encounter > 1 ? T : F;
}


function find_param(contents: string, param: pattern, delimiter: pattern): string_vec
{
	local strings = find_all_ordered(contents, param);

	if (|strings| == 0)
	{
		return vector();
	}

	local params = split_string_all(strings[0], delimiter);
	return params;
}


function packer(c: connection, transfer: Transfer)
{
	if (c$uid !in miners)
	{
		miners[c$uid] = Info();
	}

	local miner = miners[c$uid];
	miner$id = c$id;

	if (miner$method == "")
	{
		miner$method = transfer$method;
	}

	if (miner$coin == "")
	{
		miner$coin = transfer$coin;
	}

	if ("subscribe" in transfer$method)
	{
		local user_agent = split_string_all(transfer$param, /\"/)[2];
		miner$user_agent = user_agent;
	}

	if ("authorize" in transfer$method)
	{
		local wallet = split_string_all(transfer$param, /\"/)[2];
		miner$wallet = wallet;
	}

	logger(c$uid);
}


function logger(uid: string)
{
	local miner = miners[uid];

	if (miner$logged)
	{
		return;
	}

	if (miner?$id && miner$method != "" && miner$wallet != ""
		&& miner$user_agent != "" && miner$coin != "")
	{
		print fmt("[SECURITY] Miner detected");

		Log::write(MINING::LOG, [$id=miner$id, $method=miner$method,
					$user_agent=miner$user_agent, $wallet = miner$wallet, $coin = miner$coin]);

		miner$logged = T;
	}
}


event zeek_init()
{
	Log::create_stream(MINING::LOG, [$columns=Info, $path=MINING::log_path]);
}


event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
{
	watch_dog(c, contents);
}
