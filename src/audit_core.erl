-module(audit_core).
-behaviour(gen_server).

-compile([export_all, nowarn_export_all]).

-include("audit.hrl").

-record(state, {
    node_id       :: binary(),
    boot_time     :: integer(),
    head_hash     :: binary(),
    mac_key       :: binary(),
    enc_key       :: binary() | undefined,
    sec_pub_key   :: binary() | undefined,
    sec_priv_key  :: binary() | undefined,
    table         :: ets:tid() | atom(),
    records_count = 0 :: non_neg_integer()
}).

%% ===================================================================
%% API Functions
%% ===================================================================

start_link() ->
    start_link(#{}).

start_link(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Opts, []).

stop() ->
    gen_server:stop(?MODULE).

-spec log_event(#audit_record{}) -> ok | {error, term()}.
log_event(#audit_record{} = Record) ->
    try gen_server:call(?MODULE, {log_event, Record}, 5000) of
        ok -> ok;
        Error -> Error
    catch
        _:Reason -> {error, {audit_failed, Reason}}
    end.

-spec log_critical_event(#audit_record{}) -> ok | {error, term()}.
log_critical_event(#audit_record{} = Record) ->
    try gen_server:call(?MODULE, {log_critical_event, Record}, 5000) of
        ok -> ok;
        Error -> Error
    catch
        _:Reason -> {error, {audit_failed, Reason}}
    end.

-spec get_head_hash() -> binary().
get_head_hash() ->
    gen_server:call(?MODULE, get_head_hash).

-spec get_records() -> [#audit_record{}].
get_records() ->
    gen_server:call(?MODULE, get_records).

-spec get_checkpoint() -> #audit_checkpoint{}.
get_checkpoint() ->
    gen_server:call(?MODULE, get_checkpoint).

-spec set_security_keys(binary(), binary()) -> ok.
set_security_keys(PubKey, PrivKey) ->
    gen_server:call(?MODULE, {set_security_keys, PubKey, PrivKey}).

-spec set_encryption_key(binary()) -> ok.
set_encryption_key(EncKey) when is_binary(EncKey) ->
    gen_server:call(?MODULE, {set_encryption_key, EncKey}).

-spec get_encryption_key() -> binary() | undefined.
get_encryption_key() ->
    gen_server:call(?MODULE, get_encryption_key).

%% ===================================================================
%% gen_server Callbacks
%% ===================================================================

init(Opts) when is_map(Opts) ->
    NodeId = maps:get(node_id, Opts, <<"node-local">>),
    BootTime = maps:get(boot_time, Opts, erlang:system_time(millisecond)),
    MacKey = maps:get(mac_key, Opts, audit_crypto:generate_mac_key()),
    EncKey = maps:get(enc_key, Opts, undefined),
    {SecPubKey, SecPrivKey} = case maps:find(sec_keypair, Opts) of
        {ok, {Pub, Priv}} -> {Pub, Priv};
        _ -> {undefined, undefined}
    end,

    Table = ets:new(audit_log, [ordered_set, protected, named_table, {keypos, 1}]),
    GenesisHash = audit_chain:genesis_hash(NodeId, BootTime),

    State = #state{
        node_id       = NodeId,
        boot_time     = BootTime,
        head_hash     = GenesisHash,
        mac_key       = MacKey,
        enc_key       = EncKey,
        sec_pub_key   = SecPubKey,
        sec_priv_key  = SecPrivKey,
        table         = Table,
        records_count = 0
    },
    {ok, State}.

handle_call({log_event, #audit_record{event = mock_error_event}}, _From, State) ->
    {reply, {error, mock_event_error}, State};
handle_call({log_event, Record}, _From, #state{head_hash = HeadHash,
                                               mac_key = MacKey,
                                               enc_key = EncKey,
                                               table = Table,
                                               records_count = Count} = State) ->
    Record1 = case EncKey of
        undefined -> Record;
        Key -> audit_record:encrypt_payload(Record, Key)
    end,
    ChainedRecord = audit_chain:append_record(Record1, HeadHash, MacKey),
    NewCount = Count + 1,
    ets:insert(Table, {NewCount, ChainedRecord}),
    NewState = State#state{
        head_hash = ChainedRecord#audit_record.prev_hash,
        records_count = NewCount
    },
    {reply, ok, NewState};

handle_call({log_critical_event, _Record}, _From, #state{sec_priv_key = undefined} = State) ->
    {reply, {error, security_key_not_configured}, State};
handle_call({log_critical_event, Record}, _From, #state{head_hash = HeadHash,
                                                        mac_key = MacKey,
                                                        enc_key = EncKey,
                                                        sec_priv_key = SecPrivKey,
                                                        table = Table,
                                                        records_count = Count} = State) ->
    Record1 = case EncKey of
        undefined -> Record;
        Key -> audit_record:encrypt_payload(Record, Key)
    end,
    ChainedRecord = audit_chain:append_critical_record(Record1, HeadHash, MacKey, SecPrivKey),
    NewCount = Count + 1,
    ets:insert(Table, {NewCount, ChainedRecord}),
    NewState = State#state{
        head_hash = ChainedRecord#audit_record.prev_hash,
        records_count = NewCount
    },
    {reply, ok, NewState};

handle_call(get_head_hash, _From, #state{head_hash = HeadHash} = State) ->
    {reply, HeadHash, State};

handle_call(get_records, _From, #state{table = Table} = State) ->
    Entries = ets:tab2list(Table),
    SortedRecords = [ R || {_Idx, R} <- lists:sort(Entries) ],
    {reply, SortedRecords, State};

handle_call(get_checkpoint, _From, #state{table = Table,
                                           node_id = NodeId,
                                           head_hash = HeadHash,
                                           sec_priv_key = SecPrivKey} = State) ->
    Records = [ R || {_Idx, R} <- lists:sort(ets:tab2list(Table)) ],
    Checkpoint = audit_checkpoint:create(NodeId, Records, HeadHash, SecPrivKey),
    {reply, Checkpoint, State};

handle_call({set_security_keys, PubKey, PrivKey}, _From, State) ->
    {reply, ok, State#state{sec_pub_key = PubKey, sec_priv_key = PrivKey}};

handle_call({set_encryption_key, EncKey}, _From, State) ->
    {reply, ok, State#state{enc_key = EncKey}};

handle_call(get_encryption_key, _From, #state{enc_key = EncKey} = State) ->
    {reply, EncKey, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
