// import { gone } from "./gone";
import { a } from "@app/cycle/a";
import _ from "lodash";
import { readFile } from "node:fs";
import path from "path";
import type { T1 } from "./types/t1";
import "./missing";
const s = "import './gone'";
const lazy = () => import("./lazy");
/* require("left-pad") */
export const x: T1 = { n: a + _.size([]) + s.length };
void readFile; void path; void lazy;
