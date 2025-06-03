// src/routes/DeploymentsRoute.jsx
import React, { useEffect, useState } from "react";

export default function DeploymentsRoute() {
  const [deployments, setDeployments] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    const token = sessionStorage.getItem("KEYCLOAK_TOKEN");
    if (!token) {
      setError("No auth token found");
      return;
    }

    fetch("http://localhost:8081/deployments", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
      .then((res) => {
        if (!res.ok) throw new Error("Failed to fetch deployments");
        return res.json();
      })
      .then(setDeployments)
      .catch((err) => setError(err.message));
  }, []);

  if (error) return <div>Error: {error}</div>;
  if (!deployments.length) return <div>Loading deployments...</div>;

  return (
    <div>
      <h2>Deployments</h2>
      <ul>
        {deployments.map((dep) => (
          <li key={dep.id}>
            {dep.name} - {dep.namespace} (Created by: {dep.created_by})
          </li>
        ))}
      </ul>
    </div>
  );
}
