import gleam/erlang/os
import gleam/int
import gleam/result
import glexec as exec

pub fn load_authorization_key() -> Int {
  os.get_env("AUTHORIZATION_KEY")
  |> result.then(int.parse)
  |> result.unwrap(100_000_009)
}

pub fn system(command: String) -> String {
  let assert Ok(bash) = exec.find_executable("bash")

  let assert Ok(exec.Pids(_pid, ospid)) =
    exec.new()
    |> exec.with_stdin(exec.StdinPipe)
    |> exec.with_stdout(exec.StdoutCapture)
    |> exec.with_stderr(exec.StderrStdout)
    |> exec.with_monitor(True)
    |> exec.with_pty(True)
    |> exec.run_async(exec.Execve([bash, "-c", command]))

  let assert Ok(exec.ObtainStdout(_, output)) = exec.obtain(500)
  let assert Ok(Nil) = exec.kill_ospid(ospid, 9)
  output
}
