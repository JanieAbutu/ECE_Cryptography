import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AlertTriangle, Terminal } from "lucide-react";
import { motion } from "framer-motion";

export default function AttackDemoUI() {
  const [logs, setLogs] = useState([]);
  const [status, setStatus] = useState("idle");

  const pushLog = (msg) => {
    setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  const simulateAttack = async () => {
    setStatus("running");
    pushLog("Initializing attack simulation...");

    await new Promise((r) => setTimeout(r, 1000));
    pushLog("Scanning target for open ports (Nmap simulated)...");

    await new Promise((r) => setTimeout(r, 1000));
    pushLog("Discovered open port 443 – potential vulnerability detected.");

    await new Promise((r) => setTimeout(r, 1000));
    pushLog("Launching exploit payload (simulated buffer overflow)...");

    await new Promise((r) => setTimeout(r, 1000));
    pushLog("Obtained simulated remote shell.");

    setStatus("done");
    pushLog("Attack simulation completed.");
  };

  return (
    <div className="min-h-screen bg-gray-100 p-8">
      <motion.h1 layout className="text-3xl font-bold mb-6">
        Cyber Attack Simulation UI
      </motion.h1>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="shadow-xl rounded-2xl">
          <CardContent className="p-6">
            <div className="flex items-center gap-2 mb-4 text-red-600">
              <AlertTriangle />
              <h2 className="text-xl font-semibold">Attack Control Panel</h2>
            </div>

            <p className="mb-4 text-gray-700">
              Launch a simulated cyber attack demonstration. No real systems
              are harmed.
            </p>

            <Button
              className="w-full py-6 text-lg rounded-xl"
              onClick={simulateAttack}
              disabled={status === "running"}
            >
              {status === "running" ? "Simulating..." : "Start Simulation"}
            </Button>
          </CardContent>
        </Card>

        <Card className="shadow-xl rounded-2xl">
          <CardContent className="p-6">
            <div className="flex items-center gap-2 mb-4 text-gray-700">
              <Terminal />
              <h2 className="text-xl font-semibold">Simulation Logs</h2>
            </div>

            <div className="bg-black text-green-400 p-4 rounded-xl h-96 overflow-auto font-mono text-sm shadow-inner">
              {logs.map((log, i) => (
                <div key={i}>{log}</div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
