window.addEventListener("load", init);
var canvas;
var calc_canvas;

function init() {
  let vs_text = `
  attribute vec3 position;
  uniform   mat4 mvpMatrix;
  varying   vec2 vPosition;

  void main(void){
      gl_Position = mvpMatrix * vec4(position, 1.0);
      vPosition = position.xy;
  }
  `
  let fs_text = `
#ifdef GL_ES
precision mediump float;
#endif            

uniform float u_time;
uniform vec2 u_resolution;
varying vec2 vPosition;

vec3 hash(vec2 seed){
    vec3 p3 = fract(float(seed.x + seed.y*86.) * vec3(.1051, .1020, .0983));
	p3 += dot(p3, p3.yzx + 33.33);
    return fract(p3);
}

vec3 layer(float scale, vec2 uv, float time){
    // uv coord in cell
    vec2 scaled_uv = uv * scale - 0.5;
    vec2 uv0 = fract( scaled_uv ) - 0.5;
    // cell id
    vec2 cell_id = scaled_uv - fract(scaled_uv);
    
    
    vec3 col = vec3(0);
    float speed = 1.5;
    // distance to a spinning random point in the cell (also surrounding cells)
    vec3 seed = hash(cell_id);

    float radiance = seed.x + time * seed.y;
    vec2 center_of_star = vec2(sin(radiance), cos(radiance))*0.3;

    // radial distort effect for star shine
    vec2 v_to_star = uv0 - center_of_star;
    float star_radiance = atan(v_to_star.x/v_to_star.y);
    float star_spark_1 = sin(star_radiance*14.+radiance*6.);
    float star_spark_2 = sin(star_radiance*8.-radiance*2.);
    float stars = length(v_to_star) * (5.+star_spark_1+star_spark_2) * 0.03;
    col += smoothstep(length(seed) * 0.01, 0., stars);
    return col;
}
void main()
{    // center global uv from -1 to 1
    vec2 virtual_resolution = vec2(2.0, 2.0);
    vec2 uv = (vPosition * 2. - virtual_resolution.xy) / virtual_resolution.y;
    vec3 col = vec3(0.);//vColor.xyz;
    
    const float layer_count = 6.5;
    for(float i = 0.0; i < layer_count; i+=1.){
        float rotate_speed = u_time*0.4;
        float scale = mod(i - rotate_speed, layer_count)*1.5;
        vec2 offseted_uv = uv + vec2(sin(rotate_speed), cos(rotate_speed));
        vec3 layer_col = layer(scale, offseted_uv, u_time + i*1.5);
        
        // we want the star to smoothly show up
        float max_scale = layer_count * 1.5;
        float color_amp = smoothstep(0., 1., smoothstep(max_scale, 0., scale));
        col += layer_col * color_amp;
    }
    // blue background
    col += vec3(0., 0., -0.15) * (uv.y - 0.7) * pow(length(uv), 0.5);
    gl_FragColor = vec4(col, 1.);
}
  `
  let vs_calc_text = `
  attribute vec3 position;
  varying   float owO;
  
  void main(void){
      gl_Position = vec4(position.xy, 0.0, 1.0);
      owO = position.z;
  }
  `
  let fs_calc_text = `
#ifdef GL_ES
precision highp float;
#endif            
varying float owO;
#define OvO 255.0
#define Ovo 128.0
#define OVO 23.0

float OwO (float Owo, float OWO, float owO) { 
    OWO = floor(OWO + 0.5); owO = floor(owO + 0.5); 
    return mod(floor((floor(Owo) + 0.5) / exp2(OWO)), floor(1.0*exp2(owO - OWO) + 0.5)); 
}
vec4 oWo (float Ow0) { 
    if (Ow0 == 0.0) return vec4(0.0); 
    float Owo = Ow0 > 0.0 ? 0.0 : 1.0; 
    Ow0 = abs(Ow0); 
    float OWO = floor(log2(Ow0)); 
    float oWo = OWO + OvO - Ovo; 
    OWO = ((Ow0 / exp2(OWO)) - 1.0) * pow(2.0, OVO);
    float owO = oWo / 2.0; 
    oWo = fract(owO) + fract(owO); 
    float oWO = floor(owO); 
    owO = OwO(OWO, 0.0, 8.0) / OvO; 
    Ow0 = OwO(OWO, 8.0, 16.0) / OvO; 
    OWO = (oWo * Ovo + OwO(OWO, 16.0, OVO)) / OvO; 
    Owo = (Owo * Ovo + oWO) / OvO; 
    return vec4(owO, Ow0, OWO, Owo); 
}

void main()
{
    gl_FragColor = oWo(owO);
}
  `

  canvas = new renderCanvas("canvas", 0, 0, vs_text, fs_text, true);
  canvas.render();

  calc_canvas = new renderCanvas(
    "canvas-calc",
    650,
    650,
    vs_calc_text,
    fs_calc_text,
    false
  );
  calc_canvas.render();
  let container = document.getElementById("pattern-container");
  let lines = document.getElementById("lines");
  let lastDot = null;
  let curDot = null;
  let line = null;
  let x2 = null;
  let y2 = null;
  let active = false;
  let selected_nodes = [];

  container.childNodes.forEach((dot) => {
    if (!dot.classList) return;
    if (!dot.classList.contains("dot")) return;
    dot.addEventListener("mousedown", (event) => {
      selected_nodes.forEach((element) => {
        element.classList.remove("selected");
        element.classList.remove("select");
        element.classList.remove("lose");
        element.classList.remove("win");
      });
      lines.innerHTML = "";
      selected_nodes = [];
      active = true;
      dot.classList.add("select");
      line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("x1", dot.offsetLeft + dot.offsetWidth / 2);
      line.setAttribute("y1", dot.offsetTop + dot.offsetHeight / 2);
      line.setAttribute("x2", dot.offsetLeft + dot.offsetWidth / 2);
      line.setAttribute("y2", dot.offsetTop + dot.offsetHeight / 2);
      line.setAttribute("stroke", "white");
      line.setAttribute("stroke-width", "5");
      lines.appendChild(line);
      selected_nodes.push(dot);
      lastDot = dot;
    });

    dot.addEventListener("mouseover", (event) => {
      if (!active) return;
      if (dot.classList.contains("selected")) return;
      if (dot.classList.contains("select")) return;
      if (line) {
        // finish prev line
        line.setAttribute("x2", dot.offsetLeft + dot.offsetWidth / 2);
        line.setAttribute("y2", dot.offsetTop + dot.offsetHeight / 2);
        lastDot.classList.add("selected");
        lastDot.classList.remove("select");
      }
      dot.classList.add("select");
      line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("x1", dot.offsetLeft + dot.offsetWidth / 2);
      line.setAttribute("y1", dot.offsetTop + dot.offsetHeight / 2);
      line.setAttribute("x2", dot.offsetLeft + dot.offsetWidth / 2);
      line.setAttribute("y2", dot.offsetTop + dot.offsetHeight / 2);
      line.setAttribute("stroke", "white");
      line.setAttribute("stroke-width", "5");
      lines.appendChild(line);
      selected_nodes.push(dot);
      lastDot = dot;
    });
  });

  container.addEventListener("mousemove", (event) => {
    if (!active) return;
    if (lastDot && line) {
      line.setAttribute(
        "x2",
        event.clientX - container.getBoundingClientRect().left
      );
      line.setAttribute(
        "y2",
        event.clientY - container.getBoundingClientRect().top
      );
    }
  });
  container.addEventListener("mouseup", (event) => {
    if (lastDot && line) {
      line.setAttribute("x2", lastDot.offsetLeft + lastDot.offsetWidth / 2);
      line.setAttribute("y2", lastDot.offsetTop + lastDot.offsetHeight / 2);
      lastDot.classList.add("selected");
      lastDot = null;
      let res = verify(
        selected_nodes.map((element) => parseInt(element.dataset.number))
      );
      if (res !== null) {
        selected_nodes.forEach((element) => {
          element.classList.add("win");
        });
        let flag = document.getElementById("flag");
        flag.innerText = res;
      } else {
        selected_nodes.forEach((element) => {
          element.classList.add("lose");
        });
      }
    }
    active = false;
  });
}
function abs(x) {
  return Math.abs(x);
}

const getSHA256Hash = async (input) => {
  const textAsBuffer = new TextEncoder().encode(input);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", textAsBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hash = hashArray
    .map((item) => item.toString(16).padStart(2, "0"))
    .join("");
  return hash;
};

function verify(key) {

  let temp0 = calc_canvas.wtf(key[19], key[3], key[5]) * 25;
let temp1 = calc_canvas.wtf(key[7], key[20], key[18]) * 25;
let temp2 = calc_canvas.wtf(key[11], key[22], key[18]) * 25;
let temp3 = calc_canvas.wtf(key[5], key[17], key[2]) * 25;
let temp4 = calc_canvas.wtf(key[20], key[13], key[5]) * 25;
let temp5 = calc_canvas.wtf(key[11], key[1], key[21]) * 25;
let temp6 = calc_canvas.wtf(key[8], key[11], key[1]) * 25;
let temp7 = calc_canvas.wtf(key[9], key[5], key[4]) * 25;
let temp8 = calc_canvas.wtf(key[17], key[9], key[21]) * 25;
let temp9 = calc_canvas.wtf(key[23], key[9], key[20]) * 25;
let temp10 = calc_canvas.wtf(key[16], key[5], key[4]) * 25;
let temp11 = calc_canvas.wtf(key[16], key[14], key[13]) * 25;
let temp12 = calc_canvas.wtf(key[5], key[6], key[10]) * 25;
let temp13 = calc_canvas.wtf(key[2], key[11], key[5]) * 25;
let temp14 = calc_canvas.wtf(key[11], key[3], key[1]) * 25;
let temp15 = calc_canvas.wtf(key[12], key[3], key[10]) * 25;
let temp16 = calc_canvas.wtf(key[14], key[1], key[9]) * 25;
let temp17 = calc_canvas.wtf(key[18], key[11], key[17]) * 25;
let temp18 = calc_canvas.wtf(key[12], key[15], key[2]) * 25;
let temp19 = calc_canvas.wtf(key[22], key[0], key[19]) * 25;
let res = 0;
res += abs(0.3837876686390533 - calc_canvas.gtfo(temp5, temp16, temp8, 16, 21));
res += abs(0.21054889940828397 - calc_canvas.gtfo(temp14, temp5, temp6, 8, 2));
res += abs(0.475323349112426 - calc_canvas.gtfo(temp5, temp17, temp12, 0, 20));
res += abs(0.6338370887573964 - calc_canvas.gtfo(temp3, temp1, temp12, 8, 4));
res += abs(0.4111607928994082 - calc_canvas.gtfo(temp2, temp14, temp15, 23, 1));
res += abs(0.7707577751479291 - calc_canvas.gtfo(temp17, temp3, temp11, 20, 6));
res += abs(0.7743081420118344 - calc_canvas.gtfo(temp9, temp13, temp3, 9, 10));
res += abs(0.36471487573964495 - calc_canvas.gtfo(temp8, temp0, temp4, 18, 8));
res += abs(0.312678449704142 - calc_canvas.gtfo(temp15, temp9, temp17, 0, 17));
res += abs(0.9502808165680473 - calc_canvas.gtfo(temp18, temp9, temp3, 22, 10));
res += abs(0.5869052899408282 - calc_canvas.gtfo(temp12, temp7, temp2, 14, 10));
res += abs(0.9323389467455623 - calc_canvas.gtfo(temp17, temp2, temp12, 12, 7));
res += abs(0.4587118106508875 - calc_canvas.gtfo(temp6, temp13, temp2, 4, 21));
res += abs(0.14484472189349107 - calc_canvas.gtfo(temp15, temp9, temp14, 7, 15));
res += abs(0.7255550059171598 - calc_canvas.gtfo(temp5, temp17, temp18, 9, 23));
res += abs(0.5031261301775147 - calc_canvas.gtfo(temp3, temp2, temp14, 7, 1));
res += abs(0.1417352189349112 - calc_canvas.gtfo(temp6, temp14, temp8, 16, 14));
res += abs(0.5579334437869822 - calc_canvas.gtfo(temp14, temp2, temp18, 19, 11));
res += abs(0.48502262721893485 - calc_canvas.gtfo(temp10, temp4, temp7, 23, 18));
res += abs(0.5920916568047336 - calc_canvas.gtfo(temp7, temp8, temp1, 19, 6));
res += abs(0.7222713017751479 - calc_canvas.gtfo(temp16, temp2, temp4, 8, 16));
res += abs(0.12367382248520711 - calc_canvas.gtfo(temp10, temp15, temp12, 9, 5));
res += abs(0.4558028402366864 - calc_canvas.gtfo(temp11, temp10, temp2, 10, 2));
res += abs(0.8537692426035504 - calc_canvas.gtfo(temp17, temp9, temp13, 4, 11));
res += abs(0.9618170650887574 - calc_canvas.gtfo(temp12, temp18, temp17, 15, 2));
res += abs(0.22088933727810647 - calc_canvas.gtfo(temp0, temp7, temp16, 10, 5));
res += abs(0.4302783550295858 - calc_canvas.gtfo(temp16, temp11, temp5, 14, 2));
res += abs(0.6262803313609467 - calc_canvas.gtfo(temp19, temp14, temp2, 17, 22));

  if (res > 0.00001) {
    return null;
  }
  s = "";

s += Math.round(calc_canvas.wtf(key[4], key[2], key[22])*100000).toString();
s += Math.round(calc_canvas.wtf(key[17], key[9], key[14])*100000).toString();
s += Math.round(calc_canvas.wtf(key[4], key[13], key[7])*100000).toString();
s += Math.round(calc_canvas.wtf(key[4], key[20], key[23])*100000).toString();
s += Math.round(calc_canvas.wtf(key[5], key[7], key[12])*100000).toString();
s += Math.round(calc_canvas.wtf(key[20], key[19], key[4])*100000).toString();
s += Math.round(calc_canvas.wtf(key[17], key[6], key[19])*100000).toString();
s += Math.round(calc_canvas.wtf(key[6], key[21], key[18])*100000).toString();
s += Math.round(calc_canvas.wtf(key[4], key[3], key[8])*100000).toString();
s += Math.round(calc_canvas.wtf(key[11], key[7], key[14])*100000).toString();
s += Math.round(calc_canvas.wtf(key[9], key[2], key[13])*100000).toString();
s += Math.round(calc_canvas.wtf(key[22], key[10], key[3])*100000).toString();
s += Math.round(calc_canvas.wtf(key[15], key[22], key[13])*100000).toString();
s += Math.round(calc_canvas.wtf(key[16], key[12], key[9])*100000).toString();
s += Math.round(calc_canvas.wtf(key[14], key[8], key[17])*100000).toString();
s += Math.round(calc_canvas.wtf(key[1], key[18], key[6])*100000).toString();
s += Math.round(calc_canvas.wtf(key[10], key[11], key[3])*100000).toString();
s += Math.round(calc_canvas.wtf(key[8], key[12], key[5])*100000).toString();
s += Math.round(calc_canvas.wtf(key[1], key[3], key[12])*100000).toString();
s += Math.round(calc_canvas.wtf(key[9], key[13], key[7])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[22], key[13], key[5], key[4], key[7])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[10], key[14], key[17], key[23], key[11])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[23], key[20], key[6], key[1], key[3])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[15], key[12], key[2], key[13], key[9])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[16], key[20], key[6], key[5], key[18])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[3], key[6], key[7], key[8], key[23])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[21], key[9], key[10], key[3], key[22])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[14], key[6], key[15], key[12], key[19])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[13], key[19], key[22], key[23], key[1])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[21], key[2], key[9], key[0], key[19])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[5], key[19], key[21], key[14], key[6])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[16], key[15], key[20], key[13], key[3])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[20], key[15], key[10], key[21], key[6])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[7], key[1], key[21], key[20], key[3])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[9], key[20], key[1], key[10], key[6])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[10], key[2], key[1], key[16], key[4])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[15], key[5], key[20], key[19], key[8])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[20], key[8], key[21], key[10], key[12])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[19], key[5], key[4], key[2], key[22])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[10], key[20], key[14], key[9], key[7])*100000).toString();
let flag = decrypt(s);
s += Math.round(calc_canvas.gtfo(key[5], key[15], key[9], key[13], key[16])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[20], key[8], key[11], key[22], key[23])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[22], key[3], key[1], key[17], key[15])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[4], key[8], key[14], key[3], key[17])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[12], key[6], key[11], key[10], key[15])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[13], key[5], key[2], key[4], key[9])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[21], key[12], key[19], key[11], key[20])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[13], key[11], key[18], key[12], key[20])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[11], key[2], key[8], key[3], key[16])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[16], key[1], key[5], key[4], key[22])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[0], key[3], key[12], key[10], key[1])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[19], key[22], key[17], key[14], key[13])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[14], key[2], key[10], key[18], key[16])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[21], key[0], key[18], key[19], key[4])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[22], key[12], key[9], key[16], key[17])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[4], key[18], key[15], key[0], key[14])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[9], key[5], key[19], key[20], key[12])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[10], key[6], key[20], key[11], key[5])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[1], key[11], key[22], key[13], key[9])*100000).toString();
s += Math.round(calc_canvas.gtfo(key[1], key[19], key[10], key[0], key[18])*100000).toString();
  return flag;
}

function decrypt(keystring){
  let k = CryptoJS.enc.Hex.parse(CryptoJS.SHA256(keystring).toString(CryptoJS.enc.Hex));
  let iv = CryptoJS.enc.Hex.parse("fd3cb6c1be89457ba82919a33f02707c");
  let enc = CryptoJS.enc.Hex.parse(
    "4f6b9161b29e59e2d94fa90529d745601473cb4203c02d9549eea6e322908d71e0472241d86f3821b3c96dd82937b04dcef80b9f68b23dd2371d2a56ef873ce857563eefc6f9057aa0cc5b41ff87477256f6b56ef342da815099d1217d301d03b76e4fae675d27bf95ca43154015b964"
  );
  let decrypted = CryptoJS.AES.decrypt({ ciphertext: enc }, k, {
    iv: iv,
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC,
    hasher: CryptoJS.algo.SHA256,
  });
  return decrypted.toString(CryptoJS.enc.Utf8);

}

class renderCanvas {
  constructor(id, w, h, vs, fs, render) {
    this.canvas = document.getElementById(id);
    if (w != 0 && h != 0) {
      this.canvas.width = w;
      this.canvas.height = h;
    } else {
      this.canvas.width = window.innerWidth;
      this.canvas.height = window.innerHeight;
    }
    this.w = this.canvas.width;
    this.h = this.canvas.height;
    this.d = [4, 20, 23, 13, 11, 0, 15, 1, 14, 21, 9, 19, 8, 3, 17, 24, 16, 6, 22, 10, 7, 18, 2, 5, 12];

    this.timeLoad = performance.now();

    this.gl = this.canvas.getContext("webgl2");
    this.gl.getExtension("EXT_color_buffer_float");

    this.v_shader = this.create_shader(vs, "OuO");
    this.f_shader = this.create_shader(fs, ">w<");
    this.prg = this.create_program(this.v_shader, this.f_shader);

    let sandbox = this;
    function RenderLoop() {
      sandbox.render();
      sandbox.animationFrameRequest = window.requestAnimationFrame(RenderLoop);
    }
    if (render) {
      RenderLoop();
    }
    return this;
  }
  wtf(a, b, x) {
    this.gl.clearColor(0.0, 0.0, 0.0, 1.0);
    this.gl.clearDepth(1.0);
    this.gl.clear(this.gl.COLOR_BUFFER_BIT | this.gl.DEPTH_BUFFER_BIT);

    const attLocation = this.gl.getAttribLocation(this.prg, "position");
    const attStride = 3;

    const vertex_position = [
      -1,
      -1,
      (a % 1 + this.d[~~a]) / 25,
      -1,
      1,
      (b % 1 + this.d[~~b]) / 25,
      1,
      1,
      (b % 1 + this.d[~~b]) / 25,
      -1,
      -1,
      (a % 1 + this.d[~~a]) / 25,
      1,
      1,
      (b % 1 + this.d[~~b]) / 25,
      1,
      -1,
      (a % 1 + this.d[~~a]) / 25,
    ];

    const position_vbo = this.create_vbo(vertex_position);

    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, position_vbo);
    this.gl.enableVertexAttribArray(attLocation);
    this.gl.vertexAttribPointer(
      attLocation,
      attStride,
      this.gl.FLOAT,
      false,
      0,
      0
    );

    this.gl.useProgram(this.prg);
    this.gl.drawArrays(this.gl.TRIANGLES, 0, 6);
    this.gl.flush();
    const out = new Uint8Array(4);
    this.gl.readPixels(
      this.w / 2,
      (( x % 1 + this.d[~~x]) * this.h) / 25,
      1,
      1,
      this.gl.RGBA,
      this.gl.UNSIGNED_BYTE,
      out
    );
    let res = new Float32Array(out.buffer);
    return res[0].toFixed(15);
  }

  gtfo(a, b, c, x, y) {
    this.gl.clearColor(0.0, 0.0, 0.0, 1.0);
    this.gl.clearDepth(1.0);
    this.gl.clear(this.gl.COLOR_BUFFER_BIT | this.gl.DEPTH_BUFFER_BIT);

    const attLocation = this.gl.getAttribLocation(this.prg, "position");
    const attStride = 3;

    const vertex_position = [-1, -1, (a % 1 + this.d[~~a]) / 25, 3, -1, (b % 1 + this.d[~~b]) / 25, -1, 3, (c % 1 + this.d[~~c]) / 25];

    const position_vbo = this.create_vbo(vertex_position);

    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, position_vbo);
    this.gl.enableVertexAttribArray(attLocation);
    this.gl.vertexAttribPointer(
      attLocation,
      attStride,
      this.gl.FLOAT,
      false,
      0,
      0
    );

    this.gl.useProgram(this.prg);
    this.gl.drawArrays(this.gl.TRIANGLES, 0, 3);
    this.gl.flush();
    const out = new Uint8Array(4);
    this.gl.readPixels(
      ((x % 1 + this.d[~~x]) * this.w) / 25,
      ((y % 1 + this.d[~~y]) * this.h) / 25,
      1,
      1,
      this.gl.RGBA,
      this.gl.UNSIGNED_BYTE,
      out
    );
    let res = new Float32Array(out.buffer);
    return res[0].toFixed(15);
  }

  render() {
    this.gl.clearColor(0.0, 0.0, 0.0, 1.0);
    this.gl.clearDepth(1.0);
    this.gl.clear(this.gl.COLOR_BUFFER_BIT | this.gl.DEPTH_BUFFER_BIT);

    let now = performance.now();
    this.timeDelta = (now - this.timePrev) / 1000.0;
    this.timePrev = now;

    const attLocation = new Array(2);
    attLocation[0] = this.gl.getAttribLocation(this.prg, "position");

    const attStride = new Array(2);
    attStride[0] = 3;
    attStride[1] = 4;

    const vertex_position = [
      3, 8, 0, 7, -3, 5, 3, -8, 0, 3, 8, 0, 7, -3, 5, 7, 3, 5, 3, 8, 0, -3, -8,
      0, 3, -8, 0, 3, 8, 0, -3, -8, 0, -3, 8, 0, -3, 8, 0, -7, -3, 5, -3, -8, 0,
      -3, 8, 0, -7, -3, 5, -7, 3, 5,
    ];

    const position_vbo = this.create_vbo(vertex_position);

    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, position_vbo);
    this.gl.enableVertexAttribArray(attLocation[0]);
    this.gl.vertexAttribPointer(
      attLocation[0],
      attStride[0],
      this.gl.FLOAT,
      false,
      0,
      0
    );

    const m = new matIV();

    const mMatrix = m.identity(m.create());
    const vMatrix = m.identity(m.create());
    const pMatrix = m.identity(m.create());
    const mvpMatrix = m.identity(m.create());

    const u_time = (now - this.timeLoad) / 1000.0;
    const up_vec = [
      Math.sin(Math.sin(u_time) / 3),
      Math.cos(Math.sin(u_time) / 3),
      0,
    ];

    m.lookAt([0.0, 0.0, 5.0], [0, 0, 0], up_vec, vMatrix);
    m.perspective(
      90,
      this.canvas.width / this.canvas.height,
      0.1,
      100,
      pMatrix
    );
    m.multiply(pMatrix, vMatrix, mvpMatrix);
    m.multiply(mvpMatrix, mMatrix, mvpMatrix);

    const uniLocation = this.gl.getUniformLocation(this.prg, "mvpMatrix");
    this.gl.uniformMatrix4fv(uniLocation, false, mvpMatrix);

    const uTime = this.gl.getUniformLocation(this.prg, "u_time");
    this.gl.uniform1f(uTime, u_time);

    const uResolution = this.gl.getUniformLocation(this.prg, "u_resolution");
    this.gl.uniform2f(uResolution, this.canvas.width, this.canvas.height);

    this.gl.useProgram(this.prg);
    this.gl.drawArrays(this.gl.TRIANGLES, 0, 18);
    this.gl.flush();
  }
  // create shader function
  create_shader(src, type) {
    let shader;

    switch (type) {
      case "OuO":
        shader = this.gl.createShader(this.gl.VERTEX_SHADER);
        break;
      case ">w<":
        shader = this.gl.createShader(this.gl.FRAGMENT_SHADER);
        break;
      default:
        return;
    }

    this.gl.shaderSource(shader, src);
    this.gl.compileShader(shader);

    if (this.gl.getShaderParameter(shader, this.gl.COMPILE_STATUS)) {
      return shader;
    } else {
      alert(this.gl.getShaderInfoLog(shader));
    }
  }

  // create program object and link shaders
  create_program(vs, fs) {
    const program = this.gl.createProgram();

    this.gl.attachShader(program, vs);
    this.gl.attachShader(program, fs);
    this.gl.linkProgram(program);

    if (this.gl.getProgramParameter(program, this.gl.LINK_STATUS)) {
      this.gl.useProgram(program);
      return program;
    } else {
      alert(this.gl.getProgramInfoLog(program));
    }
  }

  create_vbo(data) {
    const vbo = this.gl.createBuffer();
    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, vbo);
    this.gl.bufferData(
      this.gl.ARRAY_BUFFER,
      new Float32Array(data),
      this.gl.STATIC_DRAW
    );
    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, null);
    return vbo;
  }
}
