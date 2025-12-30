-module(xtask_ffi).
-export([find_executable/1]).

find_executable(Name) ->
    case os:find_executable(binary_to_list(Name)) of
        false -> none;
        Path -> {some, list_to_binary(Path)}
    end.
