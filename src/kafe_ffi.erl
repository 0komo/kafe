-module(kafe_ffi).
-export([wrap/2]).

-type result(V, E) :: {ok, V} | {error, E}.

-type option(V) :: {some, V} | none.

-type protocol_version() :: tlsv1 | tlsv1m1 | tlsv1m2 | tlsv1m3.

-type verify() :: none | peer.

-type wrap_options() :: {wrap_options,
        ProtocolVersion :: protocol_version(),
        Alpn :: [binary()],
        Cafile :: option(binary()),
        ChiperSuites :: [binary()],
        Depth :: pos_integer(),
        Verify :: verify()    
    }.

-spec wrap(inet:socket(), wrap_options()) -> result(ssl:sslsocket(), any()).
wrap(Socket, {wrap_options, ProtocolVersion, Alpn, Cafile, ChiperSuiteNames, Depth, Verify}) ->
    maybe
        {ok, Ciphers} ?= strs_to_suites(ChiperSuiteNames),
        % eqwalizer:ignore not sure why it yells here
        ssl:connect(Socket, lists:append([
            [
                {versions, [normalise(ProtocolVersion)]},
                {alpn_advertised_protocols, Alpn},
                {cacerts, public_key:cacerts_get()},
                {ciphers, Ciphers},
                {depth, Depth},
                {verify, normalise(Verify)}
            ],
            % eqwalizer:ignore unwrap_option will always unwrap cuz of is_some
            optional(is_some(Cafile), {cacertfile, unicode:characters_to_list(unwrap_option(Cafile))})
        ]))
    end.


-spec normalise(tlsv1) -> tlsv1;
               (tlsv1m1) -> 'tlsv1.1';
               (tlsv1m2) -> 'tlsv1.2';
               (tlsv1m3) -> 'tlsv1.3';
               (none) -> verify_none;
               (peer) -> verify_peer.
%% Protocol version
normalise(tlsv1) -> tlsv1;
normalise(tlsv1m1) -> 'tlsv1.1';
normalise(tlsv1m2) -> 'tlsv1.2';
normalise(tlsv1m3) -> 'tlsv1.3';
%% Verify
normalise(none) -> verify_none;
normalise(peer) -> verify_peer.

-spec strs_to_suites([binary()]) -> result(ssl:ciphers(), {not_recognized, string()}).
strs_to_suites(Names) ->
    Unchecked = lists:map(fun(V) ->
        % eqwalizer:ignore will always return string()
        ssl:str_to_suite(unicode:characters_to_list(V))
    end, Names),
    case lists:search(fun is_error/1, Unchecked) of
        {value, {error, _} = E} -> E;
        % eqwalizer:ignore it's already handled by the lists:search
        false -> {ok, Unchecked}
    end.

-spec optional(boolean(), T) -> [T] | [].
optional(Pred, V) ->
    case Pred of
        true -> [V];
        false -> []
    end.

-spec unwrap_option(option(T)) -> T | none.
unwrap_option({some, V}) -> V;
unwrap_option(none) -> none.

-spec is_some(option(any())) -> boolean().
is_some({some, _}) -> true;
is_some(none) -> false.

-spec is_error(result(any(), any()) | any()) -> boolean().
is_error({error, _}) -> true;
is_error(_) -> false.
