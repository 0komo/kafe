import child_process
import fswalk
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import xtask/internal

pub fn main() {
  case internal.find_executable("treefm") {
    Some(_) -> {
      let assert Ok(child_process.Output(0, _)) =
        internal.exe("treefmt", []) |> child_process.run
      Nil
    }
    None -> {
      let erl_files =
        internal.traverse_directory(
          "src",
          Some(fn(e: fswalk.Entry) { string.ends_with(e.filename, ".erl") }),
        )
      let gleam_files = {
        let srcs =
          internal.traverse_directory(
            "src",
            Some(fn(e: fswalk.Entry) { string.ends_with(e.filename, ".gleam") }),
          )
        let tests =
          internal.traverse_directory(
            "test",
            Some(fn(e: fswalk.Entry) { string.ends_with(e.filename, ".gleam") }),
          )

        list.append(srcs, tests)
      }

      let assert Ok(_) =
        internal.exe("erlfmt", ["-w", ..erl_files])
        |> child_process.run

      let assert Ok(_) =
        internal.exe("gleam", ["format", ..gleam_files])
        |> child_process.run

      Nil
    }
  }
}
