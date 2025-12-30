import child_process
import child_process/stdio
import fswalk
import gleam/option.{type Option, None, Some}
import gleam/yielder

@external(erlang, "xtask_ffi", "find_executable")
pub fn find_executable(exe: String) -> Option(String)

pub fn exe(exe: String, args: List(String)) -> child_process.Builder {
  child_process.new_with_path(exe)
  |> child_process.args(args)
  |> child_process.stdio(stdio.inherit())
}

pub fn traverse_directory(
  path: String,
  filter filter: Option(fswalk.EntryFilter),
) -> List(String) {
  let builder =
    fswalk.builder()
    |> fswalk.with_path(path)

  builder
  |> fswalk.walk
  |> yielder.map(fn(e) {
    let assert Ok(e) = e
    e
  })
  |> yielder.filter(case filter {
    Some(filter) -> filter
    None -> fn(_) { True }
  })
  |> yielder.fold([], fn(acc, it) { [it.filename, ..acc] })
}
