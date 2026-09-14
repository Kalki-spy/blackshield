import { createContext, useContext, useState, ReactNode } from "react";

export type TeamMode = "red" | "blue" | "explorer";

interface TeamModeContextType {
  mode: TeamMode;
  setMode: (mode: TeamMode) => void;
}

const TeamModeContext = createContext<TeamModeContextType>({
  mode: "red",
  setMode: () => {},
});

export const useTeamMode = () => useContext(TeamModeContext);

export function TeamModeProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<TeamMode>("red");
  return (
    <TeamModeContext.Provider value={{ mode, setMode }}>
      {children}
    </TeamModeContext.Provider>
  );
}
