import logging
import time
import re
from typing import Any, Dict, List

from vectorai_app.core.models import CTFChallenge
from vectorai_app.workflows.manager import CTFWorkflowManager
from vectorai_app.tools.manager import CTFToolManager

logger = logging.getLogger(__name__)

class CTFChallengeAutomator:
    """Advanced automation system for CTF challenge solving"""

    def __init__(self):
        self.active_challenges = {}
        self.solution_cache = {}
        self.learning_database = {}
        self.success_patterns = {}
        self.workflow_manager = CTFWorkflowManager()
        self.tool_manager = CTFToolManager()

    def auto_solve_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """Attempt to automatically solve a CTF challenge"""
        result = {
            "challenge_id": challenge.name,
            "status": "in_progress",
            "automated_steps": [],
            "manual_steps": [],
            "confidence": 0.0,
            "estimated_completion": 0,
            "artifacts": [],
            "flag_candidates": [],
            "next_actions": []
        }

        try:
            # Create workflow
            workflow = self.workflow_manager.create_ctf_challenge_workflow(challenge)

            # Execute automated steps
            for step in workflow["workflow_steps"]:
                if step.get("parallel", False):
                    step_result = self._execute_parallel_step(step, challenge)
                else:
                    step_result = self._execute_sequential_step(step, challenge)

                result["automated_steps"].append(step_result)

                # Check for flag candidates
                flag_candidates = self._extract_flag_candidates(step_result.get("output", ""))
                result["flag_candidates"].extend(flag_candidates)

                # Update confidence based on step success
                if step_result.get("success", False):
                    result["confidence"] += 0.1

                # Early termination if flag found
                if flag_candidates and self._validate_flag_format(flag_candidates[0]):
                    result["status"] = "solved"
                    result["flag"] = flag_candidates[0]
                    break

            # If not solved automatically, provide manual guidance
            if result["status"] != "solved":
                result["manual_steps"] = self._generate_manual_guidance(challenge, result)
                result["status"] = "needs_manual_intervention"

            result["confidence"] = min(1.0, result["confidence"])

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"Error in auto-solve for {challenge.name}: {str(e)}")

        return result

    def _execute_parallel_step(self, step: Dict[str, Any], challenge: CTFChallenge) -> Dict[str, Any]:
        """Execute a step with parallel tool execution"""
        step_result = {
            "step": step["step"],
            "action": step["action"],
            "success": False,
            "output": "",
            "tools_used": [],
            "execution_time": 0,
            "artifacts": []
        }

        start_time = time.time()
        tools = step.get("tools", [])

        # Execute tools in parallel (simulated for now)
        for tool in tools:
            try:
                if tool != "manual":
                    command = self.tool_manager.get_tool_command(tool, challenge.url or challenge.name)
                    # In a real implementation, this would execute the command
                    step_result["tools_used"].append(tool)
                    step_result["output"] += f"[{tool}] Executed successfully\n"
                    step_result["success"] = True
            except Exception as e:
                step_result["output"] += f"[{tool}] Error: {str(e)}\n"

        step_result["execution_time"] = time.time() - start_time
        return step_result

    def _execute_sequential_step(self, step: Dict[str, Any], challenge: CTFChallenge) -> Dict[str, Any]:
        """Execute a step sequentially"""
        step_result = {
            "step": step["step"],
            "action": step["action"],
            "success": False,
            "output": "",
            "tools_used": [],
            "execution_time": 0,
            "artifacts": []
        }

        start_time = time.time()
        tools = step.get("tools", [])

        for tool in tools:
            try:
                if tool == "manual":
                    step_result["output"] += f"[MANUAL] {step['description']}\n"
                    step_result["success"] = True
                elif tool == "custom":
                    step_result["output"] += f"[CUSTOM] Custom implementation required\n"
                    step_result["success"] = True
                else:
                    command = self.tool_manager.get_tool_command(tool, challenge.url or challenge.name)
                    step_result["tools_used"].append(tool)
                    step_result["output"] += f"[{tool}] Command: {command}\n"
                    step_result["success"] = True
            except Exception as e:
                step_result["output"] += f"[{tool}] Error: {str(e)}\n"

        step_result["execution_time"] = time.time() - start_time
        return step_result

    def _extract_flag_candidates(self, output: str) -> List[str]:
        """Extract potential flags from tool output"""
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'[a-zA-Z0-9_]+\{[^}]+\}',
            r'[0-9a-f]{32}',  # MD5 hash
            r'[0-9a-f]{40}',  # SHA1 hash
            r'[0-9a-f]{64}'   # SHA256 hash
        ]

        candidates = []
        for pattern in flag_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            candidates.extend(matches)

        return list(set(candidates))  # Remove duplicates

    def _validate_flag_format(self, flag: str) -> bool:
        """Validate if a string matches common flag formats"""
        common_formats = [
            r'^flag\{.+\}$',
            r'^FLAG\{.+\}$',
            r'^ctf\{.+\}$',
            r'^CTF\{.+\}$',
            r'^[a-zA-Z0-9_]+\{.+\}$'
        ]

        for pattern in common_formats:
            if re.match(pattern, flag, re.IGNORECASE):
                return True

        return False

    def _generate_manual_guidance(self, challenge: CTFChallenge, current_result: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate manual guidance when automation fails"""
        guidance = []

        # Analyze what was attempted
        attempted_tools = []
        for step in current_result["automated_steps"]:
            attempted_tools.extend(step.get("tools_used", []))

        # Suggest alternative approaches
        all_category_tools = self.tool_manager.get_category_tools(f"{challenge.category}_recon")
        unused_tools = [tool for tool in all_category_tools if tool not in attempted_tools]

        if unused_tools:
            guidance.append({
                "action": "try_alternative_tools",
                "description": f"Try these alternative tools: {', '.join(unused_tools[:3])}"
            })

        # Category-specific guidance
        if challenge.category == "web":
            guidance.extend([
                {"action": "manual_source_review", "description": "Manually review all HTML/JS source code for hidden comments or clues"},
                {"action": "parameter_fuzzing", "description": "Manually fuzz parameters with custom payloads"},
                {"action": "cookie_analysis", "description": "Analyze cookies and session management"}
            ])
        elif challenge.category == "crypto":
            guidance.extend([
                {"action": "cipher_research", "description": "Research the specific cipher type and known attacks"},
                {"action": "key_analysis", "description": "Analyze key properties and potential weaknesses"},
                {"action": "frequency_analysis", "description": "Perform detailed frequency analysis"}
            ])
        elif challenge.category == "pwn":
            guidance.extend([
                {"action": "manual_debugging", "description": "Manually debug the binary to understand control flow"},
                {"action": "exploit_development", "description": "Develop custom exploit based on vulnerability analysis"},
                {"action": "payload_crafting", "description": "Craft specific payloads for the identified vulnerability"}
            ])
        elif challenge.category == "forensics":
            guidance.extend([
                {"action": "manual_analysis", "description": "Manually analyze file structures and metadata"},
                {"action": "steganography_deep_dive", "description": "Deep dive into steganography techniques"},
                {"action": "timeline_analysis", "description": "Reconstruct detailed timeline of events"}
            ])
        elif challenge.category == "rev":
            guidance.extend([
                {"action": "algorithm_analysis", "description": "Focus on understanding the core algorithm"},
                {"action": "key_extraction", "description": "Extract hardcoded keys or important values"},
                {"action": "dynamic_analysis", "description": "Use dynamic analysis to understand runtime behavior"}
            ])

        return guidance

class CTFTeamCoordinator:
    """Coordinate team efforts in CTF competitions"""

    def __init__(self):
        self.team_members = {}
        self.challenge_assignments = {}
        self.team_communication = []
        self.shared_resources = {}

    def optimize_team_strategy(self, challenges: List[CTFChallenge], team_skills: Dict[str, List[str]]) -> Dict[str, Any]:
        """Optimize team strategy based on member skills and challenge types"""
        strategy = {
            "assignments": {},
            "priority_queue": [],
            "collaboration_opportunities": [],
            "resource_sharing": {},
            "estimated_total_score": 0,
            "time_allocation": {}
        }

        # Analyze team skills
        skill_matrix = {}
        for member, skills in team_skills.items():
            skill_matrix[member] = {
                "web": "web" in skills or "webapp" in skills,
                "crypto": "crypto" in skills or "cryptography" in skills,
                "pwn": "pwn" in skills or "binary" in skills,
                "forensics": "forensics" in skills or "investigation" in skills,
                "rev": "reverse" in skills or "reversing" in skills,
                "osint": "osint" in skills or "intelligence" in skills,
                "misc": True  # Everyone can handle misc
            }

        # Score challenges for each team member
        member_challenge_scores = {}
        for member in team_skills.keys():
            member_challenge_scores[member] = []

            for challenge in challenges:
                base_score = challenge.points
                skill_multiplier = 1.0

                if skill_matrix[member].get(challenge.category, False):
                    skill_multiplier = 1.5  # 50% bonus for skill match

                difficulty_penalty = {
                    "easy": 1.0,
                    "medium": 0.9,
                    "hard": 0.7,
                    "insane": 0.5,
                    "unknown": 0.8
                }[challenge.difficulty]

                final_score = base_score * skill_multiplier * difficulty_penalty

                member_challenge_scores[member].append({
                    "challenge": challenge,
                    "score": final_score,
                    "estimated_time": self._estimate_solve_time(challenge, skill_matrix[member])
                })

        # Assign challenges using Hungarian algorithm approximation
        assignments = self._assign_challenges_optimally(member_challenge_scores)
        strategy["assignments"] = assignments

        # Create priority queue
        all_assignments = []
        for member, challenges in assignments.items():
            for challenge_info in challenges:
                all_assignments.append({
                    "member": member,
                    "challenge": challenge_info["challenge"].name,
                    "priority": challenge_info["score"],
                    "estimated_time": challenge_info["estimated_time"]
                })

        strategy["priority_queue"] = sorted(all_assignments, key=lambda x: x["priority"], reverse=True)

        # Identify collaboration opportunities
        strategy["collaboration_opportunities"] = self._identify_collaboration_opportunities(challenges, team_skills)

        return strategy

    def _estimate_solve_time(self, challenge: CTFChallenge, member_skills: Dict[str, bool]) -> int:
        """Estimate solve time for a challenge based on member skills"""
        base_times = {
            "easy": 1800,    # 30 minutes
            "medium": 3600,  # 1 hour
            "hard": 7200,    # 2 hours
            "insane": 14400, # 4 hours
            "unknown": 5400  # 1.5 hours
        }

        base_time = base_times[challenge.difficulty]

        # Skill bonus
        if member_skills.get(challenge.category, False):
            base_time = int(base_time * 0.7)  # 30% faster with relevant skills

        return base_time

    def _assign_challenges_optimally(self, member_challenge_scores: Dict[str, List[Dict]]) -> Dict[str, List[Dict]]:
        """Assign challenges to team members optimally"""
        assignments = {member: [] for member in member_challenge_scores.keys()}
        assigned_challenges = set()

        # Simple greedy assignment (in practice, would use Hungarian algorithm)
        for _ in range(len(member_challenge_scores)):
            best_assignment = None
            best_score = -1

            for member, challenge_scores in member_challenge_scores.items():
                for challenge_info in challenge_scores:
                    challenge_name = challenge_info["challenge"].name
                    if challenge_name not in assigned_challenges:
                        if challenge_info["score"] > best_score:
                            best_score = challenge_info["score"]
                            best_assignment = (member, challenge_info)

            if best_assignment:
                member, challenge_info = best_assignment
                assignments[member].append(challenge_info)
                assigned_challenges.add(challenge_info["challenge"].name)

        return assignments

    def _identify_collaboration_opportunities(self, challenges: List[CTFChallenge], team_skills: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Identify challenges that would benefit from team collaboration"""
        collaboration_opportunities = []

        for challenge in challenges:
            if challenge.difficulty in ["hard", "insane"]:
                # High-difficulty challenges benefit from collaboration
                relevant_members = []
                for member, skills in team_skills.items():
                    if challenge.category in [skill.lower() for skill in skills]:
                        relevant_members.append(member)

                if len(relevant_members) >= 2:
                    collaboration_opportunities.append({
                        "challenge": challenge.name,
                        "recommended_team": relevant_members,
                        "reason": f"High-difficulty {challenge.category} challenge benefits from collaboration"
                    })

        return collaboration_opportunities
