export function run(input) {
  eval(input) // limier-ignore sast.eval -- input comes from our own config
  // limier-ignore sast.eval, quality.debugger -- kept on purpose for the demo

  eval(input)
  eval(input)
  // limier-ignore
  eval(input)
}
