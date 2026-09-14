import { Link } from "react-router-dom";
import { ArrowRight } from "lucide-react";
import { services } from "@/data/services";

export function ServicesGrid() {
  return (
    <section className="py-24 relative" id="services">
      <div className="container mx-auto px-4">
        <div className="text-center mb-16">
          <p className="text-xs font-mono text-primary mb-2 tracking-widest uppercase">// Our Services</p>
          <h2 className="text-3xl md:text-4xl font-bold font-mono text-foreground">
            Comprehensive <span className="gradient-text">Cyber Defense</span>
          </h2>
          <p className="text-muted-foreground mt-4 max-w-xl mx-auto">
            End-to-end security solutions covering every layer of your infrastructure.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-6xl mx-auto">
          {services.map((service) => (
            <Link key={service.id} to={`/services/${service.id}`} className="group">
              <div className="neon-card rounded-lg p-6 h-full flex flex-col">
                <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
                  <service.icon className={`h-6 w-6 ${service.color}`} />
                </div>
                <h3 className="font-mono font-semibold text-foreground mb-2">{service.title}</h3>
                <p className="text-sm text-muted-foreground flex-1">{service.description}</p>
                <div className="flex items-center gap-2 mt-4 text-primary text-sm font-mono opacity-0 group-hover:opacity-100 transition-opacity">
                  <span>Explore</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </div>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}
