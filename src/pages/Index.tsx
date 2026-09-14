import { Navbar } from "@/components/Navbar";
import { HeroSection } from "@/components/HeroSection";
import { CapabilitiesSection } from "@/components/CapabilitiesSection";
import { Chatbot } from "@/components/Chatbot";

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <HeroSection />
      <CapabilitiesSection />
      <Chatbot />
    </div>
  );
};

export default Index;
