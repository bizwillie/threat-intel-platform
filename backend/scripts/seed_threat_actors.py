"""
Threat Actor Database Seeding Script (Phase 6)

Populates the database with known APT groups and their associated TTPs.

Data sources:
- MITRE ATT&CK groups
- Curated threat intelligence
- Weighted by frequency/significance of technique usage

Usage:
    python -m scripts.seed_threat_actors

Run from backend/ directory.
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.database import AsyncSessionLocal

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Threat actor data with techniques and weights
# Weight interpretation: 0.0-1.0 where 1.0 = signature technique, 0.5 = commonly used, 0.1 = occasionally used
THREAT_ACTORS = {
    "APT29": {
        "name": "Cozy Bear (APT29)",
        "description": "Russian cyber espionage group associated with SVR. Known for sophisticated operations targeting governments, think tanks, and organizations. Active since at least 2008.",
        "techniques": {
            "T1059.001": 0.95,  # PowerShell - signature
            "T1059.003": 0.85,  # Windows Command Shell
            "T1566.001": 0.90,  # Spearphishing Attachment
            "T1566.002": 0.85,  # Spearphishing Link
            "T1071.001": 0.80,  # Web Protocols for C2
            "T1071.004": 0.70,  # DNS for C2
            "T1090.002": 0.75,  # External Proxy
            "T1027": 0.85,      # Obfuscated Files or Information
            "T1047": 0.80,      # Windows Management Instrumentation
            "T1053.005": 0.70,  # Scheduled Task
            "T1055": 0.75,      # Process Injection
            "T1082": 0.65,      # System Information Discovery
            "T1083": 0.60,      # File and Directory Discovery
            "T1087": 0.55,      # Account Discovery
            "T1005": 0.70,      # Data from Local System
            "T1039": 0.60,      # Data from Network Shared Drive
            "T1041": 0.75,      # Exfiltration Over C2 Channel
            "T1567": 0.65,      # Exfiltration Over Web Service
        }
    },
    "APT28": {
        "name": "Fancy Bear (APT28)",
        "description": "Russian military intelligence (GRU) cyber operations group. Conducts espionage and influence operations targeting governments, militaries, and security organizations. Active since at least 2004.",
        "techniques": {
            "T1566.001": 0.95,  # Spearphishing Attachment - signature
            "T1566.002": 0.90,  # Spearphishing Link
            "T1189": 0.85,      # Drive-by Compromise
            "T1190": 0.80,      # Exploit Public-Facing Application
            "T1203": 0.85,      # Exploitation for Client Execution
            "T1059.001": 0.75,  # PowerShell
            "T1059.003": 0.70,  # Windows Command Shell
            "T1071.001": 0.85,  # Web Protocols for C2
            "T1105": 0.80,      # Ingress Tool Transfer
            "T1053.005": 0.75,  # Scheduled Task
            "T1543.003": 0.70,  # Windows Service
            "T1055": 0.65,      # Process Injection
            "T1027": 0.80,      # Obfuscated Files or Information
            "T1082": 0.70,      # System Information Discovery
            "T1057": 0.65,      # Process Discovery
            "T1083": 0.65,      # File and Directory Discovery
            "T1113": 0.75,      # Screen Capture
            "T1005": 0.70,      # Data from Local System
            "T1041": 0.80,      # Exfiltration Over C2 Channel
        }
    },
    "APT1": {
        "name": "Comment Crew (APT1)",
        "description": "Chinese cyber espionage group associated with PLA Unit 61398. Targets intellectual property and sensitive data from organizations worldwide. Active since at least 2006.",
        "techniques": {
            "T1566.001": 0.90,  # Spearphishing Attachment
            "T1059.003": 0.85,  # Windows Command Shell
            "T1071.001": 0.90,  # Web Protocols for C2
            "T1105": 0.85,      # Ingress Tool Transfer
            "T1053.005": 0.80,  # Scheduled Task
            "T1547.001": 0.75,  # Registry Run Keys
            "T1082": 0.75,      # System Information Discovery
            "T1083": 0.70,      # File and Directory Discovery
            "T1057": 0.70,      # Process Discovery
            "T1005": 0.85,      # Data from Local System
            "T1039": 0.75,      # Data from Network Shared Drive
            "T1074": 0.80,      # Data Staged
            "T1560": 0.75,      # Archive Collected Data
            "T1041": 0.85,      # Exfiltration Over C2 Channel
        }
    },
    "Lazarus": {
        "name": "Lazarus Group",
        "description": "North Korean state-sponsored group conducting cyber espionage, sabotage, and financially-motivated attacks. Notable for WannaCry ransomware and bank heists. Active since at least 2009.",
        "techniques": {
            "T1566.001": 0.90,  # Spearphishing Attachment
            "T1204.002": 0.85,  # Malicious File
            "T1059.003": 0.80,  # Windows Command Shell
            "T1059.001": 0.75,  # PowerShell
            "T1071.001": 0.85,  # Web Protocols for C2
            "T1105": 0.80,      # Ingress Tool Transfer
            "T1486": 0.95,      # Data Encrypted for Impact - signature
            "T1490": 0.85,      # Inhibit System Recovery
            "T1489": 0.80,      # Service Stop
            "T1027": 0.85,      # Obfuscated Files or Information
            "T1055": 0.75,      # Process Injection
            "T1082": 0.70,      # System Information Discovery
            "T1083": 0.65,      # File and Directory Discovery
            "T1005": 0.75,      # Data from Local System
            "T1041": 0.80,      # Exfiltration Over C2 Channel
        }
    },
    "FIN7": {
        "name": "Carbanak (FIN7)",
        "description": "Russian cybercriminal group targeting financial services, hospitality, and retail sectors. Known for sophisticated point-of-sale malware and BEC attacks. Active since at least 2013.",
        "techniques": {
            "T1566.001": 0.95,  # Spearphishing Attachment - signature
            "T1566.002": 0.85,  # Spearphishing Link
            "T1204.002": 0.90,  # Malicious File
            "T1059.001": 0.80,  # PowerShell
            "T1059.003": 0.75,  # Windows Command Shell
            "T1059.005": 0.70,  # Visual Basic
            "T1071.001": 0.85,  # Web Protocols for C2
            "T1105": 0.80,      # Ingress Tool Transfer
            "T1027": 0.85,      # Obfuscated Files or Information
            "T1140": 0.75,      # Deobfuscate/Decode Files
            "T1055": 0.80,      # Process Injection
            "T1082": 0.70,      # System Information Discovery
            "T1083": 0.70,      # File and Directory Discovery
            "T1056.001": 0.85,  # Keylogging
            "T1005": 0.80,      # Data from Local System
            "T1113": 0.75,      # Screen Capture
            "T1041": 0.85,      # Exfiltration Over C2 Channel
        }
    },
    "APT41": {
        "name": "Double Dragon (APT41)",
        "description": "Chinese state-sponsored group conducting both espionage and financially-motivated attacks. Unique dual mandate targeting governments, technology, healthcare, and gaming sectors. Active since at least 2012.",
        "techniques": {
            "T1190": 0.90,      # Exploit Public-Facing Application - signature
            "T1133": 0.85,      # External Remote Services
            "T1078": 0.80,      # Valid Accounts
            "T1566.001": 0.75,  # Spearphishing Attachment
            "T1059.001": 0.80,  # PowerShell
            "T1059.003": 0.75,  # Windows Command Shell
            "T1071.001": 0.85,  # Web Protocols for C2
            "T1105": 0.80,      # Ingress Tool Transfer
            "T1053.005": 0.75,  # Scheduled Task
            "T1543.003": 0.70,  # Windows Service
            "T1027": 0.80,      # Obfuscated Files or Information
            "T1055": 0.75,      # Process Injection
            "T1082": 0.70,      # System Information Discovery
            "T1083": 0.70,      # File and Directory Discovery
            "T1005": 0.75,      # Data from Local System
            "T1041": 0.80,      # Exfiltration Over C2 Channel
        }
    },
    "Sandworm": {
        "name": "Sandworm Team",
        "description": "Russian military intelligence (GRU) group conducting disruptive and destructive cyber operations. Responsible for NotPetya and attacks on Ukrainian infrastructure. Active since at least 2009.",
        "techniques": {
            "T1190": 0.85,      # Exploit Public-Facing Application
            "T1059.003": 0.80,  # Windows Command Shell
            "T1059.001": 0.75,  # PowerShell
            "T1071.001": 0.80,  # Web Protocols for C2
            "T1105": 0.80,      # Ingress Tool Transfer
            "T1486": 0.95,      # Data Encrypted for Impact - signature
            "T1485": 0.90,      # Data Destruction
            "T1561": 0.85,      # Disk Wipe
            "T1490": 0.85,      # Inhibit System Recovery
            "T1027": 0.80,      # Obfuscated Files or Information
            "T1082": 0.70,      # System Information Discovery
            "T1083": 0.65,      # File and Directory Discovery
            "T1005": 0.70,      # Data from Local System
        }
    },
    "Turla": {
        "name": "Turla (Snake/Uroburos)",
        "description": "Russian FSB-associated cyber espionage group with sophisticated tooling and tradecraft. Long-term operations targeting governments, embassies, and defense organizations. Active since at least 1996.",
        "techniques": {
            "T1566.001": 0.85,  # Spearphishing Attachment
            "T1189": 0.80,      # Drive-by Compromise
            "T1195.002": 0.90,  # Compromise Software Supply Chain - signature
            "T1059.001": 0.85,  # PowerShell
            "T1059.003": 0.80,  # Windows Command Shell
            "T1071.001": 0.85,  # Web Protocols for C2
            "T1071.004": 0.75,  # DNS for C2
            "T1573": 0.80,      # Encrypted Channel
            "T1090": 0.85,      # Proxy
            "T1027": 0.90,      # Obfuscated Files or Information
            "T1140": 0.75,      # Deobfuscate/Decode Files
            "T1055": 0.80,      # Process Injection
            "T1082": 0.70,      # System Information Discovery
            "T1083": 0.70,      # File and Directory Discovery
            "T1005": 0.75,      # Data from Local System
            "T1041": 0.85,      # Exfiltration Over C2 Channel
        }
    },
}


async def seed_threat_actors():
    """Seed the database with threat actor data."""
    logger.info("Starting threat actor database seeding...")

    async with AsyncSessionLocal() as session:
        try:
            # Clear existing data
            logger.info("Clearing existing threat actor data...")
            await session.execute(text("DELETE FROM actor_techniques"))
            await session.execute(text("DELETE FROM threat_actors"))
            await session.commit()

            # Insert threat actors and their techniques
            for actor_id, actor_data in THREAT_ACTORS.items():
                logger.info(f"Inserting {actor_id}: {actor_data['name']}")

                # Insert threat actor
                await session.execute(
                    text("""
                        INSERT INTO threat_actors (id, name, description)
                        VALUES (:id, :name, :description)
                    """),
                    {
                        "id": actor_id,
                        "name": actor_data["name"],
                        "description": actor_data["description"]
                    }
                )

                # Insert actor techniques
                technique_count = 0
                for technique_id, weight in actor_data["techniques"].items():
                    await session.execute(
                        text("""
                            INSERT INTO actor_techniques (actor_id, technique_id, weight)
                            VALUES (:actor_id, :technique_id, :weight)
                        """),
                        {
                            "actor_id": actor_id,
                            "technique_id": technique_id,
                            "weight": weight
                        }
                    )
                    technique_count += 1

                logger.info(f"  ✓ Inserted {technique_count} techniques for {actor_id}")

            await session.commit()

            # Verify insertion
            result = await session.execute(text("SELECT COUNT(*) FROM threat_actors"))
            actor_count = result.scalar()

            result = await session.execute(text("SELECT COUNT(*) FROM actor_techniques"))
            technique_count = result.scalar()

            logger.info(f"\n✅ Seeding complete!")
            logger.info(f"   Threat actors inserted: {actor_count}")
            logger.info(f"   Actor techniques inserted: {technique_count}")

        except Exception as e:
            logger.error(f"❌ Error seeding threat actors: {e}")
            await session.rollback()
            raise


async def verify_seeding():
    """Verify the seeding was successful."""
    logger.info("\nVerifying threat actor data...")

    async with AsyncSessionLocal() as session:
        # Check each actor
        for actor_id in THREAT_ACTORS.keys():
            result = await session.execute(
                text("""
                    SELECT name,
                           (SELECT COUNT(*) FROM actor_techniques WHERE actor_id = :actor_id) as technique_count
                    FROM threat_actors
                    WHERE id = :actor_id
                """),
                {"actor_id": actor_id}
            )

            row = result.fetchone()
            if row:
                logger.info(f"  ✓ {actor_id}: {row[0]} - {row[1]} techniques")
            else:
                logger.error(f"  ✗ {actor_id}: NOT FOUND")


if __name__ == "__main__":
    asyncio.run(seed_threat_actors())
    asyncio.run(verify_seeding())
