import { useEffect, useRef, useState } from "react";
import * as d3 from "d3";

const COLORS = { green: "#34d399", yellow: "#fbbf24", red: "#f87171" };

export default function AutopsyVisualizer({ data }) {
  const svgRef = useRef(null);
  const wrapRef = useRef(null);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    if (!data) return;
    const width = wrapRef.current?.clientWidth || 900;
    const height = 640;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();
    svg.attr("width", width).attr("height", height);

    const g = svg.append("g");

    const defs = svg.append("defs");
    const pattern = defs
      .append("pattern")
      .attr("id", "grid-pattern")
      .attr("width", 24)
      .attr("height", 24)
      .attr("patternUnits", "userSpaceOnUse");
    pattern.append("path").attr("d", "M 24 0 L 0 0 0 24").attr("fill", "none").attr("stroke", "#1e2a45").attr("strokeWidth", 0.5);
    svg.append("rect").attr("width", width).attr("height", height).attr("fill", "url(#grid-pattern)");

    const zoom = d3
      .zoom()
      .scaleExtent([0.3, 4])
      .on("zoom", (event) => g.attr("transform", event.transform));
    svg.call(zoom);

    const nodes = data.nodes.map((n) => ({ ...n }));
    const links = data.links.map((l) => ({ ...l }));

    const simulation = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3.forceLink(links).id((d) => d.id).distance(110).strength(0.35)
      )
      .force("charge", d3.forceManyBody().strength(-260))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collide", d3.forceCollide().radius(34));

    const link = g
      .append("g")
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke", "#334368")
      .attr("strokeOpacity", 0.6)
      .attr("strokeWidth", 1);

    const node = g
      .append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .style("cursor", "pointer")
      .on("click", (_, d) => setSelected(d))
      .call(drag(simulation));

    const radiusByGroup = {
      file: 22,
      section: 12,
      import: 10,
      function: 7,
      certificate: 16,
      resource: 12,
      strings: 14,
      yara: 16,
    };

    node
      .append("circle")
      .attr("r", (d) => radiusByGroup[d.group] || 10)
      .attr("fill", (d) => COLORS[d.risk] || "#64748b")
      .attr("fillOpacity", 0.9)
      .attr("stroke", "#0b1120")
      .attr("strokeWidth", 2)
      .attr("class", "node-circle")
      .attr("style", (d) => `filter: drop-shadow(0 0 6px ${COLORS[d.risk] || "#64748b"})`);

    node
      .append("text")
      .attr("dy", (d) => (radiusByGroup[d.group] || 10) + 14)
      .attr("text-anchor", "middle")
      .attr("fill", "#94a3b8")
      .attr("font-size", 9)
      .attr("font-family", "JetBrains Mono, monospace")
      .text((d) => (d.label.length > 22 ? d.label.slice(0, 20) + "…" : d.label));

    link
      .attr("x1", (d) => d.source.x)
      .attr("y1", (d) => d.source.y)
      .attr("x2", (d) => d.target.x)
      .attr("y2", (d) => d.target.y);

    node.attr("transform", (d) => `translate(${d.x},${d.y})`);

    simulation.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);
      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });

    return () => simulation.stop();
  }, [data]);

  function drag(simulation) {
    function dragstarted(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }
    function dragged(event, d) {
      d.fx = event.x;
      d.fy = event.y;
    }
    function dragended(event, d) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }
    return d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended);
  }

  const total = data?.nodes?.length || 0;
  const suspicious = data?.nodes?.filter((n) => n.risk !== "green").length || 0;

  return (
    <div ref={wrapRef} className="relative rounded-xl border border-slate-700/60 bg-[#0d1526] overflow-hidden">
      <div className="absolute top-3 left-4 z-10 flex gap-3 text-[11px] font-mono">
        <span className="px-2 py-0.5 rounded bg-slate-900/80 border border-slate-700 text-slate-300">
          NODES <b className="text-cyan-300">{total}</b>
        </span>
        <span className="px-2 py-0.5 rounded bg-slate-900/80 border border-slate-700 text-slate-300">
          FLAGGED <b className="text-red-400">{suspicious}</b>
        </span>
      </div>
      <div className="absolute bottom-3 right-4 z-10 flex gap-3 text-[11px] font-mono">
        {Object.entries(COLORS).map(([k, v]) => (
          <span key={k} className="flex items-center gap-1.5 text-slate-400">
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: v, boxShadow: `0 0 6px ${v}` }} />
            {k}
          </span>
        ))}
      </div>
      <svg ref={svgRef} className="block" />
      {selected && (
        <div className="absolute bottom-16 left-4 z-10 max-w-xs rounded-lg border border-cyan-500/40 bg-slate-900/95 p-3 shadow-xl">
          <div className="flex items-center gap-2 mb-1">
            <span className="w-3 h-3 rounded-full" style={{ background: COLORS[selected.risk], boxShadow: `0 0 8px ${COLORS[selected.risk]}` }} />
            <span className="font-semibold text-cyan-300 text-sm font-mono">{selected.label}</span>
          </div>
          <p className="text-xs text-slate-300 font-mono break-words">{selected.details || "No details"}</p>
          <button
            onClick={() => setSelected(null)}
            className="mt-2 text-[11px] text-slate-500 hover:text-cyan-300 font-mono"
          >
            [close]
          </button>
        </div>
      )}
    </div>
  );
}
